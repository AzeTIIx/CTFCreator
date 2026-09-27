"""__SLUG__ — service TCP (une connexion = un échange). Remplacer `handle` par la logique du challenge."""

import asyncio
import os

FLAG = os.environ.get("CTFD_FLAG") or os.environ.get("FLAG") or "CCTF{local_test_only}"
TIMEOUT = 60


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(b"__SLUG__ > mot de passe ? ")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), TIMEOUT)
        # TODO : la faiblesse du challenge ici
        if line.strip() == b"TODO":
            writer.write(f"bravo : {FLAG}\n".encode())
        else:
            writer.write(b"non.\n")
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()


async def main() -> None:
    server = await asyncio.start_server(handle, "0.0.0.0", 1337, limit=4096)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
