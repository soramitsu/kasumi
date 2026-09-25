use kasumi_private_evidence::collection_definitions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let definitions = collection_definitions("evidence_manifests", "evidence_chunks")?;
    println!("{}", serde_json::to_string(&definitions)?);
    Ok(())
}
