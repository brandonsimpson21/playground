pub mod error;
pub mod tracing;

#[cfg(test)]
mod tests {
    use crate::error::PlaygroundError;

    use super::*;

    #[test]
    fn playground()-> Result<(), PlaygroundError> {

        Ok(())
    }
}
