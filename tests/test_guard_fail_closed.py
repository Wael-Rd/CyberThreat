import asyncio,subprocess,sys
from pathlib import Path
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
ROOT=Path(__file__).resolve().parents[1]
async def main():
    def guard(action): subprocess.run([sys.executable,str(ROOT/'scripts/host_guard.py'),action],check=True,capture_output=True)
    async with stdio_client(StdioServerParameters(command=sys.executable,args=[str(ROOT/'mcp_server/server.py')])) as (r,w):
        async with ClientSession(r,w) as client:
            await client.initialize()
            try:
                guard('remove')
                result=await client.call_tool('static_triage',{'sample':'harmless-training.txt'})
                assert result.isError, 'Static tool accepted missing host guard'
            finally: guard('apply')
            result=await client.call_tool('static_triage',{'sample':'harmless-training.txt'})
            assert not result.isError
    print('PASS: static triage fails closed without host guard; guard restored and call succeeds')
asyncio.run(main())
