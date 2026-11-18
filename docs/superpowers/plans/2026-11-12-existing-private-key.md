# Existing private key login

Approved design: reference the original local private key; never generate a replacement or install remote authorization. Keep password bootstrap available. Optional passphrase is transient. Verify host identity and public-key authentication before saving an alias. Encrypted keys may require a terminal passphrase or ssh-agent for subsequent use.

1. Add regression coverage to the local SSH fixture for existing-key authentication, unchanged key bytes and no installation command.
2. Add PrivateKeyPath/Passphrase request fields and an independent connection verification branch before EnsureKey. Validate config-safe absolute paths, preserve original files, and report encrypted-key limitations.
3. Add native form mode, path/passphrase fields, accurate confirmation text and secret cleanup.
4. Run Go tests and build the application.
