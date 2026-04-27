import asyncio

async def read(reader: asyncio.StreamReader) -> bytes:
    # in: <len(data)>:<data>,
    # out: data (bytes)
    try:
        length = await reader.readuntil(b':')
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            return None
        raise ValueError('Missing or corrupt netstring header')

    if len(length) > 6:
        raise ValueError('Invalid length')

    length = int(length[:-1])
    if length > 65535:
        raise ValueError('Length exceeds limit')

    try:
        data = await reader.readexactly(length + 1)
    except asyncio.IncompleteReadError as e:
        raise ValueError('Truncated netstring')

    if data[-1:] != b',':
        raise ValueError('Missing delimiter at end of netstring')

    return data[:-1]

def write(writer: asyncio.StreamWriter, data: bytes):
    # in: bytes
    # out: <len(bytes)>:<bytes>,
    writer.writelines([
        f'{len(data)}:'.encode(),
        data,
        b','
    ])


async def read_dict(reader: asyncio.StreamReader) -> dict[str, bytes]:
    # in: b'4:none,0:,4:true,1:t,5:false,1:f,5:bytes,14:ba\x00byte\x01string,3:str,17:sa unicode string,3:int,4:i123,0:,'
    # out: {'none': None, 'true': True, 'false': False, 'bytes': b'a\x00byte\x01string', 'str': 'a unicode string', 'int': 123}
    obj = None
    while True:
        key = await read(reader)
        if key is None:
            if obj is None:
                return None
            raise ValueError('Unexpected EOF')

        if obj is None:
            obj = {}

        if key == b'':
            break

        key = key.decode()

        value = await read(reader)
        if value is None:
            raise ValueError('Missing value')

        if value == b'':
            value = None
        else:
            tag, value = value[0:1], value[1:]
            if tag == b't':
                value = True
            elif tag == b'f':
                value = False
            elif tag == b'b':
                value = value
            elif tag == b's':
                value = value.decode()
            elif tag == b'i':
                value = int(value)
            else:
                raise ValueError(f'Invalid type {str(tag)} for {key}')

        obj[key] = value

    return obj

def write_dict(writer: asyncio.StreamWriter, obj: dict[str, bytes]):
    # in: {'none': None, 'true': True, 'false': False, 'bytes': b'a\x00byte\x01string', 'str': 'a unicode string', 'int': 123}
    # out: b'4:none,0:,4:true,1:t,5:false,1:f,5:bytes,14:ba\x00byte\x01string,3:str,17:sa unicode string,3:int,4:i123,0:,'
    payload = []
    for k, v in obj.items():
        payload.extend([
            f'{len(k)}:'.encode(),
            k.encode(),
            b','
        ])

        if v is None:
            payload.append(b'0:,')
        elif isinstance(v, bool):
            if v:
                payload.append(b'1:t,')
            else:
                payload.append(b'1:f,')
        elif isinstance(v, bytes):
            payload.extend([
                f'{1 + len(v)}:'.encode(),
                b'b', v,
                b','
            ])
        elif isinstance(v, str):
            v = v.encode()
            payload.extend([
                f'{1 + len(v)}:'.encode(),
                b's', v,
                b','
            ])
        elif isinstance(v, int):
            v = str(v).encode()
            payload.extend([
                f'{1 + len(v)}:'.encode(),
                b'i', v,
                b','
            ])
        else:
            raise ValueError(f'Can not serialize "{k}" of type {type(v).__name__}')

    payload.append(b'0:,')
    writer.writelines(payload)
