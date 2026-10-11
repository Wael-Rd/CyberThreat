import asyncio, json, sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
ROOT=Path(__file__).resolve().parents[1]
async def main():
    params=StdioServerParameters(command=sys.executable,args=[str(ROOT/'mcp_server/server.py')])
    async with stdio_client(params) as (r,w):
        async with ClientSession(r,w) as client:
            await client.initialize()
            tools=await client.list_tools()
            assert {x.name for x in tools.tools}=={'lab_status','run_detection_demo','list_evidence','read_evidence','static_triage'}
            for args in ({'run':'../../etc','artifact':'results.json'},{'run':'run-any','artifact':'/etc/shadow'}):
                result=await client.call_tool('read_evidence',args)
                assert result.isError, 'path escape accepted'
            result=await client.call_tool('static_triage',{'sample':'../README.md'})
            assert result.isError
            for sample in ('harmless-training.txt; id','/etc/passwd'):
                blocked=await client.call_tool('static_triage',{'sample':sample})
                assert blocked.isError
            link=ROOT/'samples'/'security-symlink-control.txt'
            oversized=ROOT/'samples'/'security-oversize-control.bin'
            try:
                link.symlink_to(ROOT/'README.md')
                with oversized.open('wb') as f: f.truncate(10*1024*1024+1)
                for sample in (link.name,oversized.name):
                    blocked=await client.call_tool('static_triage',{'sample':sample})
                    assert blocked.isError
            finally:
                link.unlink(missing_ok=True); oversized.unlink(missing_ok=True)
            runs=await client.call_tool('list_evidence',{})
            assert not runs.isError
            reference=ROOT/'evidence/reference.json'
            if reference.exists():
                run_id=json.loads(reference.read_text())['run']
                summary_result=await client.call_tool('read_evidence',{'run':run_id,'artifact':'evidence-summary.json'})
                assert not summary_result.isError
                assert json.loads(summary_result.content[0].text)['checks_passed']==7
            print('PASS MCP stdio: 5 tools; traversal, shell metacharacters, symlink, oversize and arbitrary artifact rejection')
            if '--demo' in sys.argv:
                result=await client.call_tool('run_detection_demo',{})
                assert not result.isError, result
                print('PASS live MCP: full bounded detection demo')
            if '--docker' in sys.argv:
                for name,args in [('lab_status',{}),('static_triage',{'sample':'harmless-training.txt'})]:
                    result=await client.call_tool(name,args)
                    assert not result.isError, result
                    if name=='static_triage':
                        content=json.loads(result.content[0].text)
                        assert content['analysis']['executed'] is False
                        assert 'https://telemetry.invalid/training' in content['analysis']['network_indicators_untrusted']
                    print('PASS live Docker MCP:',name)
asyncio.run(main())
