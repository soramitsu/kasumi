//! Allocation-free token admission. Stock serde is only called after this scan.
use super::resources::{Call, exhausted, invalid};
use crate::ClientError;

struct Scan<'a> {
    input: &'a [u8],
    index: usize,
    nodes: usize,
    charge: u64,
    call: &'a Call,
}
/// One aggregate preflight budget across every JSON body in a unary response.
#[derive(Default)]
pub(crate) struct TokenBudget {
    nodes: usize,
    charge: u64,
    json_bytes: usize,
}
impl TokenBudget {
    pub(crate) fn metadata(
        &mut self,
        bytes: usize,
        nodes: usize,
        call: &Call,
    ) -> Result<(), ClientError> {
        call.check()?;
        self.nodes = self.nodes.checked_add(nodes).ok_or_else(exhausted)?;
        self.charge = self
            .charge
            .checked_add((bytes as u64).checked_mul(8).ok_or_else(exhausted)?)
            .and_then(|n| n.checked_add((nodes as u64).checked_mul(512)?))
            .ok_or_else(exhausted)?;
        if self.nodes > call.limits.max_nodes || self.charge > call.limits.max_decoded_bytes {
            return Err(exhausted());
        }
        Ok(())
    }
}
pub(crate) fn admit(input: &[u8], call: &Call) -> Result<(), ClientError> {
    admit_with(input, call, &mut TokenBudget::default())
}
pub(crate) fn admit_with(
    input: &[u8],
    call: &Call,
    budget: &mut TokenBudget,
) -> Result<(), ClientError> {
    call.check()?;
    budget.json_bytes = budget
        .json_bytes
        .checked_add(input.len())
        .ok_or_else(exhausted)?;
    if budget.json_bytes > call.limits.max_json_bytes {
        return Err(exhausted());
    }
    std::str::from_utf8(input).map_err(|_| invalid("native JSON is not UTF-8"))?;
    let mut scan = Scan {
        input,
        index: 0,
        nodes: budget.nodes,
        charge: budget.charge,
        call,
    };
    scan.space()?;
    scan.value(0)?;
    scan.space()?;
    if scan.index != input.len() {
        return Err(invalid("trailing native JSON tokens"));
    }
    budget.nodes = scan.nodes;
    budget.charge = scan.charge;
    call.check()
}
impl Scan<'_> {
    fn advance(&mut self, count: usize) -> Result<(), ClientError> {
        let old = self.index;
        self.index = self.index.checked_add(count).ok_or_else(exhausted)?;
        if self.index > self.input.len() {
            return Err(invalid("truncated snapshot JSON"));
        }
        if old / 1024 != self.index / 1024 {
            self.call.check()?;
        }
        Ok(())
    }
    fn peek(&self) -> Option<u8> {
        self.input.get(self.index).copied()
    }
    fn charge(&mut self, bytes: u64) -> Result<(), ClientError> {
        self.charge = self.charge.checked_add(bytes).ok_or_else(exhausted)?;
        if self.charge > self.call.limits.max_decoded_bytes {
            return Err(exhausted());
        }
        Ok(())
    }
    fn node(&mut self) -> Result<(), ClientError> {
        self.call.check()?;
        self.nodes = self.nodes.checked_add(1).ok_or_else(exhausted)?;
        if self.nodes > self.call.limits.max_nodes {
            return Err(exhausted());
        }
        // Includes Value/container capacity, inspected metadata and final DTO
        // overlap. This is a versioned accounting model, not allocator telemetry.
        self.charge(512)
    }
    fn space(&mut self) -> Result<(), ClientError> {
        while matches!(self.peek(), Some(b' ' | b'\r' | b'\n' | b'\t')) {
            self.advance(1)?;
        }
        Ok(())
    }
    fn byte(&mut self, expected: u8) -> Result<(), ClientError> {
        if self.peek() != Some(expected) {
            return Err(invalid("invalid snapshot JSON syntax"));
        }
        self.advance(1)
    }
    fn literal(&mut self, literal: &[u8]) -> Result<(), ClientError> {
        if !self.input[self.index..].starts_with(literal) {
            return Err(invalid("invalid snapshot JSON literal"));
        }
        self.advance(literal.len())
    }
    fn value(&mut self, depth: usize) -> Result<(), ClientError> {
        self.node()?;
        match self.peek() {
            Some(b'"') => self.string(),
            Some(b'n') => self.literal(b"null"),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'[' | b'{') => {
                if depth >= self.call.limits.max_depth {
                    return Err(exhausted());
                }
                let object = self.peek() == Some(b'{');
                let close = if object { b'}' } else { b']' };
                self.advance(1)?;
                self.space()?;
                if self.peek() == Some(close) {
                    return self.advance(1);
                }
                loop {
                    if object {
                        self.node()?;
                        self.string()?;
                        self.space()?;
                        self.byte(b':')?;
                        self.space()?;
                    }
                    self.value(depth + 1)?;
                    self.space()?;
                    if self.peek() == Some(close) {
                        return self.advance(1);
                    }
                    self.byte(b',')?;
                    self.space()?;
                }
            }
            _ => Err(invalid("invalid snapshot JSON value")),
        }
    }
    fn hex4(&mut self) -> Result<u16, ClientError> {
        let mut result = 0u16;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(b'0'..=b'9') => self.peek().unwrap() - b'0',
                Some(b'a'..=b'f') => self.peek().unwrap() - b'a' + 10,
                Some(b'A'..=b'F') => self.peek().unwrap() - b'A' + 10,
                _ => return Err(invalid("invalid JSON Unicode escape")),
            };
            result = (result << 4) | u16::from(digit);
            self.advance(1)?;
        }
        Ok(result)
    }
    fn string(&mut self) -> Result<(), ClientError> {
        self.byte(b'"')?;
        let mut decoded = 0usize;
        loop {
            let bytes = match self.peek() {
                Some(b'"') => {
                    self.advance(1)?;
                    break;
                }
                Some(b'\\') => {
                    self.advance(1)?;
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.advance(1)?;
                            1
                        }
                        Some(b'u') => {
                            self.advance(1)?;
                            let first = self.hex4()?;
                            if (0xd800..=0xdbff).contains(&first) {
                                self.byte(b'\\')?;
                                self.byte(b'u')?;
                                let second = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(invalid("invalid JSON surrogate pair"));
                                }
                                4
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err(invalid("unpaired JSON surrogate"));
                            } else if first < 0x80 {
                                1
                            } else if first < 0x800 {
                                2
                            } else {
                                3
                            }
                        }
                        _ => return Err(invalid("invalid JSON escape")),
                    }
                }
                Some(0..=31) | None => return Err(invalid("invalid JSON string")),
                Some(_) => {
                    self.advance(1)?;
                    1
                }
            };
            decoded = decoded.checked_add(bytes).ok_or_else(exhausted)?;
            if decoded > self.call.limits.max_string_bytes {
                return Err(exhausted());
            }
            self.charge((bytes as u64) * 8)?;
        }
        Ok(())
    }
    fn number(&mut self) -> Result<(), ClientError> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.advance(1)?;
        }
        match self.peek() {
            Some(b'0') => self.advance(1)?,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.numeric_byte(start)?;
                }
            }
            _ => return Err(invalid("invalid JSON number")),
        }
        if self.peek() == Some(b'.') {
            self.numeric_byte(start)?;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(invalid("invalid JSON fraction"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.numeric_byte(start)?;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.numeric_byte(start)?;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.numeric_byte(start)?;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(invalid("invalid JSON exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.numeric_byte(start)?;
            }
        }
        let length = self.index - start;
        if length > self.call.limits.max_number_bytes {
            return Err(exhausted());
        }
        self.charge((length as u64).checked_mul(8).ok_or_else(exhausted)?)
    }
    fn numeric_byte(&mut self, start: usize) -> Result<(), ClientError> {
        if self.index - start >= self.call.limits.max_number_bytes {
            return Err(exhausted());
        }
        self.advance(1)
    }
}

pub(crate) fn literal(input: &[u8], call: &Call) -> Result<serde_json::Value, ClientError> {
    call.check()?;
    let mut scan = Scan {
        input,
        index: 0,
        nodes: 0,
        charge: 0,
        call,
    };
    scan.space()?;
    let result = scan.build(0)?;
    scan.space()?;
    if scan.index != input.len() {
        return Err(invalid("trailing document JSON tokens"));
    }
    call.check()?;
    Ok(result)
}
impl Scan<'_> {
    fn decoded_string(&mut self) -> Result<String, ClientError> {
        let start = self.index;
        self.string()?;
        Ok(serde_json::from_slice(&self.input[start..self.index])?)
    }
    fn build(&mut self, depth: usize) -> Result<serde_json::Value, ClientError> {
        use serde_json::Value;
        self.node()?;
        Ok(match self.peek() {
            Some(b'"') => Value::String(self.decoded_string()?),
            Some(b'n') => {
                self.literal(b"null")?;
                Value::Null
            }
            Some(b't') => {
                self.literal(b"true")?;
                Value::Bool(true)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Value::Bool(false)
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.index;
                self.number()?;
                let text = std::str::from_utf8(&self.input[start..self.index])
                    .map_err(|_| invalid("invalid numeric bytes"))?;
                Value::Number(text.parse::<serde_json::Number>()?)
            }
            Some(b'[') => {
                if depth >= self.call.limits.max_depth {
                    return Err(exhausted());
                }
                self.advance(1)?;
                self.space()?;
                let mut values = Vec::new();
                if self.peek() != Some(b']') {
                    loop {
                        values.push(self.build(depth + 1)?);
                        self.space()?;
                        if self.peek() == Some(b']') {
                            break;
                        }
                        self.byte(b',')?;
                        self.space()?;
                    }
                }
                self.byte(b']')?;
                Value::Array(values)
            }
            Some(b'{') => {
                if depth >= self.call.limits.max_depth {
                    return Err(exhausted());
                }
                self.advance(1)?;
                self.space()?;
                let mut values = serde_json::Map::new();
                if self.peek() != Some(b'}') {
                    loop {
                        self.node()?;
                        let key = self.decoded_string()?;
                        self.space()?;
                        self.byte(b':')?;
                        self.space()?;
                        let value = self.build(depth + 1)?;
                        // Literal document keys, including serde's internal marker
                        // spellings, remain ordinary object keys.
                        values.insert(key, value);
                        self.space()?;
                        if self.peek() == Some(b'}') {
                            break;
                        }
                        self.byte(b',')?;
                        self.space()?;
                    }
                }
                self.byte(b'}')?;
                Value::Object(values)
            }
            _ => return Err(invalid("invalid document JSON value")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientDecodeLimits, ClientResources, SnapshotReadOptions};
    fn call() -> Call {
        SnapshotReadOptions {
            expected_incarnation: uuid::Uuid::new_v4(),
            resources: ClientResources::new(64 << 20, 2).unwrap(),
            limits: ClientDecodeLimits {
                max_request_bytes: 1024,
                max_wire_bytes: 65536,
                max_json_bytes: 65536,
                max_depth: 4,
                max_nodes: 32,
                max_string_bytes: 8,
                max_number_bytes: 8,
                max_rows: 4,
                max_decoded_bytes: 1 << 20,
            },
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
        }
        .admit()
        .unwrap()
    }
    #[test]
    fn scans_ignored_duplicate_and_shallow_tokens_before_serde() {
        let call = call();
        for input in [
            r#"{"x": [[[[[]]]]]}"#,
            r#"[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"#,
            r#"{"x": 123456789, "x": 1}"#,
            r#""\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061\u0061""#,
        ] {
            assert!(admit(input.as_bytes(), &call).is_err(), "{input}");
        }
        admit(br#"{"x":"\ud83d\ude00","x":-1.25e2}"#, &call).unwrap();
        for input in ["01", "1e", "[1,]", "{\"x\":}", "\"\\ud800\""] {
            assert!(admit(input.as_bytes(), &call).is_err());
        }
    }
}
