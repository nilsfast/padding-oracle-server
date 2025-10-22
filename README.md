# padding-oracle-server

A simple padding oracle server for testing padding oracle attacks.

## Usage

On startup, the server outputs it's key (can be configured in `main.py`), the padded plaintext, and the corresponding ciphertext.
You can then use the known protocol to query the server at `localhost:12345`.

The key_id is ignored.
