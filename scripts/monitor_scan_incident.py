"""Maintain one owner-assigned incident for the daily production scan check."""
import json
import os

from catalogue_promotion import REPO, request

MARKER = '<!-- cveharbor-daily-scan-monitor -->'
TITLE = 'Daily production scan check needs attention'


def main():
    headers = {'Authorization':'Bearer '+os.environ['GITHUB_TOKEN']}
    def api(path, body=None):
        with request(REPO+path, headers, body) as response:
            return json.load(response)

    page = 1
    incident = None
    while not incident:
        issues = api(f'/issues?state=open&creator=github-actions%5Bbot%5D&per_page=100&page={page}')
        incident = next((i for i in issues if i['user']['login']=='github-actions[bot]'
                         and (i.get('body') or '').startswith(MARKER) and 'pull_request' not in i),None)
        if len(issues)<100:
            break
        page+=1
    run = os.environ['GITHUB_RUN_ID']
    attempt = os.environ['GITHUB_RUN_ATTEMPT']
    assert run.isdigit() and attempt.isdigit()
    link = f'https://github.com/Prat007ai/cveharbor/actions/runs/{run}/attempts/{attempt}'
    if os.environ['CHECK_RESULT']=='success':
        if incident:
            from urllib.request import Request, build_opener
            from catalogue_promotion import NoRedirect
            api(f"/issues/{incident['number']}/comments",{'body':f'Both scan windows and the vendor comparison passed. [Recovery run]({link})'})
            req=Request(REPO+f"/issues/{incident['number']}",method='PATCH',data=b'{"state":"closed"}',
                        headers={**headers,'Content-Type':'application/json','User-Agent':'CVEHarbor monitoring'})
            with build_opener(NoRedirect).open(req,timeout=45):
                pass
        return
    message = ('The production scan check found a missed advisory or could not complete verification. '
               f'[Open the check results]({link}) for the affected products, windows and available vendor evidence.')
    if incident:
        api(f"/issues/{incident['number']}/comments",{'body':message})
    else:
        api('/issues',{'title':TITLE,'body':MARKER+'\n'+message,'assignees':['Prat007ai']})


if __name__=='__main__':
    main()
