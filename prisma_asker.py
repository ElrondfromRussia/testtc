import requests

from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

prismaUrl = "%papi_url%"
failureMask = {
    "high": 1,
    "medium": 10,
    "low": 30,
    "operator": "or"
}
filename = "%fname%"
prismaUser = "%prisma_user%"
prismaPass = "%prisma_psw%"
attemptNumber = 5
timeout = 2000


def check_code(code, mustbe, ex):
    if code != mustbe:
        print(code, mustbe)
        raise BaseException(ex)


if __name__ == "__main__":
    GlobalOk = True
    try:
        # login
        print("login:", f"{prismaUrl}/login")
        repl = requests.post(url=f"{prismaUrl}/login",
                             json={
                                 "username": prismaUser,
                                 "password": prismaPass,
                             },
                             headers={
                                 "Accept": "application/vnd.api+json",
                                 'content-type': "application/vnd.api+json",
                             },
                             verify=False)

        # #################################################
        check_code(repl.status_code, 200, "bad login")
        # #################################################

        token = repl.json().get("token")

        headers = {
            "Accept": "application/vnd.api+json",
            'content-type': "application/vnd.api+json",
            'x-redlock-auth': token,
        }

        # create asset
        repl = requests.post(url=f"{prismaUrl}/iac/v2/scans",
                             json={
                                 "data": {
                                     "type": "async-scan",
                                     "attributes": {
                                         "assetName": "my-asset",
                                         "assetType": "IaC-API",
                                         "tags": {
                                             "env": "dev"
                                         },
                                         "scanAttributes": {
                                             "projectName": "my-project"
                                         },
                                         "failureCriteria": failureMask
                                     }
                                 }
                             },
                             headers=headers,
                             verify=False)

        # #################################################
        check_code(repl.status_code, 201, "bad add asset")
        # #################################################

        # upload files
        assetId = repl.json().get("data").get("id")
        assetUrl = repl.json().get("data").get("links").get("url")

        requests.put(url=assetUrl,
                     data=open(filename, 'rb'),
                     headers=headers,
                     verify=False
                     )

        # start job
        repl = requests.post(url=f"{prismaUrl}/iac/v2/scans/{assetId}",
                             json={
                                 "data": {
                                     "id": assetId,
                                     "attributes": {
                                         "templateType": "tf"
                                     }
                                 }
                             },
                             headers=headers,
                             verify=False)

        # #################################################
        check_code(repl.status_code, 200, "bad scan start")
        # #################################################

        # waiting for job end (need max retry number)
        isReady = False
        isOk = False

        for i in range(0, attemptNumber):
            repl = requests.get(url=f"{prismaUrl}/iac/v2/scans/{assetId}/status",
                                headers=headers,
                                verify=False)

            # jwt token is dead
            if repl.status_code == 401:
                repl2 = requests.get(url=f"{prismaUrl}/auth_token/extend",
                                     headers=headers,
                                     verify=False)

                # refresh token
                check_code(repl2.status_code, 200, "bad token refresh")
                headers = {
                    "Accept": "application/vnd.api+json",
                    'content-type': "application/vnd.api+json",
                    'x-redlock-auth': repl2.json().get("token"),
                }

            if repl.status_code == 200:
                isOk = True
                status = repl.json().get("attributes").get("status")

                if status != "processing":
                    isReady = True
                    break

        if isReady and isOk:
            # get scan results and write to file
            repl = requests.get(url=f"{prismaUrl}/iac/v2/scans/{assetId}/results",
                                headers=headers,
                                verify=False)

            if repl.status_code == 200:
                with open("res.txt", "w") as f:
                    f.write(repl.json())
            else:
                print("bad getting ready result")
                raise BaseException("bad getting ready result")
        elif not isReady and isOk:
            print("too long waiting")
            raise BaseException("too long waiting")
        elif not isOk:
            print("bad getting scan res")
            raise BaseException("bad getting scan res")
    except BaseException as ex:
        print(ex)
        with open("res.txt", "w") as f:
            f.write(ex.__str__())
        GlobalOk = False
    finally:
        if not GlobalOk:
            exit(666)
