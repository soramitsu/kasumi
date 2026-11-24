use lindera::segmenter::Segmenter;
use tantivy::tokenizer::{Token, TokenStream, Tokenizer};

#[derive(Clone)]
pub(super) struct JapaneseTokenizer {
    segmenter: Segmenter,
    token: Token,
}

impl JapaneseTokenizer {
    pub(super) fn new(segmenter: Segmenter) -> Self {
        Self {
            segmenter,
            token: Token::default(),
        }
    }
}

impl Tokenizer for JapaneseTokenizer {
    type TokenStream<'a> = JapaneseTokens<'a>;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        self.token.reset();
        // The pinned, unfiltered Segmenter accepts every UTF-8 string with the
        // initialized embedded dictionary. Tantivy's tokenizer API is infallible.
        let tokens = self
            .segmenter
            .segment(text.into())
            .expect("embedded IPADIC segmenter failed");
        JapaneseTokens {
            segments: tokens.into_iter(),
            token: &mut self.token,
        }
    }
}

pub(super) struct JapaneseTokens<'a> {
    segments: std::vec::IntoIter<lindera::token::Token<'a>>,
    token: &'a mut Token,
}

impl TokenStream for JapaneseTokens<'_> {
    fn advance(&mut self) -> bool {
        let Some(segment) = self.segments.next() else {
            return false;
        };
        self.token.text = segment.surface.into_owned();
        self.token.offset_from = segment.byte_start;
        self.token.offset_to = segment.byte_end;
        self.token.position = segment.position;
        self.token.position_length = segment.position_length;
        true
    }

    fn token(&self) -> &Token {
        self.token
    }

    fn token_mut(&mut self) -> &mut Token {
        self.token
    }
}

#[cfg(test)]
mod tests {
    use super::super::analyzer;
    use kasumi_types::Analyzer;
    use tantivy::tokenizer::TokenStream;
    use unicode_normalization::UnicodeNormalization;

    /// Recorded with the previous lindera-tantivy 5.0.1 implementation.
    #[test]
    fn japanese_v1_preserves_deployed_token_text_offsets_and_positions() {
        type ExpectedToken = (String, usize, usize, usize, usize);
        let corpus: Vec<(String, Vec<ExpectedToken>)> =
            serde_json::from_str(include_str!("japanese_v1_tokens.json")).unwrap();
        let mut analyzer = analyzer(Analyzer::JapaneseV1, false).unwrap();
        for (input, expected) in corpus {
            let normalized: String = input.nfkc().collect();
            let mut actual = Vec::new();
            analyzer.token_stream(&normalized).process(&mut |token| {
                actual.push((
                    token.text.clone(),
                    token.offset_from,
                    token.offset_to,
                    token.position,
                    token.position_length,
                ));
            });
            assert_eq!(actual, expected, "{input:?}");
        }
    }
}
