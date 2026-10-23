"""Plesk XML API client: responses are parsed with defusedxml (no entity expansion, no DTD)."""

from __future__ import annotations

import httpx
import pytest

from pleskmcp.plesk_api import KeyAuth, PleskClient, PleskError

pytestmark = pytest.mark.anyio


async def _client_returning(body: bytes) -> PleskClient:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body, headers={"content-type": "text/xml"}))
    return PleskClient("https://plesk.example.com:8443", verify_ssl=True, timeout=5, transport=transport)


async def test_xml_entities_and_dtd_are_rejected():
    bomb = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><packet><system><status>&lol2;</status></system></packet>'
    client = await _client_returning(bomb)
    try:
        with pytest.raises(PleskError, match="invalid XML"):
            await client.call("<server><get><gen_info/></get></server>", KeyAuth("k"))
    finally:
        await client.aclose()
    xxe = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY f SYSTEM "file:///etc/passwd">]><packet><system><status>&f;</status></system></packet>'
    client = await _client_returning(xxe)
    try:
        with pytest.raises(PleskError, match="invalid XML"):
            await client.call("<server><get><gen_info/></get></server>", KeyAuth("k"))
    finally:
        await client.aclose()


async def test_plain_xml_still_parses():
    client = await _client_returning(b'<?xml version="1.0"?><packet version="1.6.9.1"><server><get><result><status>ok</status></result></get></server></packet>')
    try:
        root = await client.call("<server><get><gen_info/></get></server>", KeyAuth("k"))
        assert root.find("./server/get/result/status").text == "ok"
    finally:
        await client.aclose()
