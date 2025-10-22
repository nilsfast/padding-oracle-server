# padding-oracle-server

A simple padding oracle server for testing padding oracle attacks.

![A meme](https://en.meming.world/images/en/b/be/But_It%27s_Honest_Work.jpg)

## Usage

```bash
uv run main.py
```

On startup, the server outputs it's key (can be configured in `main.py`), the padded plaintext, and the corresponding ciphertext.
You can then use the known protocol to query the server at `localhost:12345`.

The key_id is ignored.

Two test cases are included for your convenience.

## Protocol

| Direction        | Size        | Description      |
| ---------------- | ----------- | ---------------- |
| Client -> Server | 2 bytes     | Key ID (ignored) |
| Client -> Server | 16 bytes    | Ciphertext Block |
| Client -> Server | 2 bytes     | Length (l) [1]   |
| Client -> Server | l\*16 bytes | Q Blocks         |
| Server -> Client | l bytes     | Response Data    |

[1] if l == 0, the server closes the connection.

## License

This software is offered without any warranty. Use at your own risk.
