import requests
import sys
from send_alert import send_mail

YA_HOST = ""
YA_PORT = 0
YA_USER = ""
YA_PASSWORD = ""
SENDER = ""

prismaUrl = "https://10.244.3.119:8083"
failureMask = {
    "high": 1,
    "medium": 10,
    "low": 30,
    "operator": "or"
}
filename = "check_res.txt"
prismaUser = "admin"
prismaPass = "admin"
attemptNumber = 5
timeout = 2000

if __name__ == "__main__":
    if len(sys.argv) == 6:
        SENDER = sys.argv[1]
        YA_HOST = sys.argv[2]
        YA_PORT = sys.argv[3]
        YA_USER = sys.argv[4]
        YA_PASSWORD = sys.argv[5]
    else:
        print("no args for mail alert")
        exit(666)

    GlobalOk = True
    try:
        # login
        repl = requests.post(url=f"{prismaUrl}/login",
                             json={
                                 "username": prismaUser,
                                 "password": prismaPass,
                             },
                             headers={
                                 'content-type': "application/vnd.api+json",
                             },
                             verify=False)
        if repl.status_code == 200:
            token = repl.json().get("token")

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
                                 headers={
                                     'content-type': "application/vnd.api+json",
                                     'x-redlock-auth': token},
                                 verify=False)

            if repl.status_code == 201:
                # upload files
                assetId = repl.json().get("data").get("id")
                assetUrl = repl.json().get("data").get("links").get("url")

                requests.put(url=assetUrl,
                             data=open(filename, 'rb'),
                             headers={
                                 'content-type': "application/vnd.api+json",
                                 'x-redlock-auth': token},
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
                                     headers={
                                         'content-type': "application/vnd.api+json",
                                         'x-redlock-auth': token},
                                     verify=False)

                if repl.status_code == 200:
                    # waiting for job end (need max retry number)
                    isReady = False
                    isOk = False

                    for i in range(0, attemptNumber):
                        repl = requests.get(url=f"{prismaUrl}/iac/v2/scans/{assetId}/status",
                                            headers={
                                                'content-type': "application/vnd.api+json",
                                                'x-redlock-auth': token},
                                            verify=False)

                        # jwt token is dead
                        if repl.status_code == 401:
                            requests.get(url=f"{prismaUrl}/auth_token/extend",
                                         headers={
                                             'content-type': "application/vnd.api+json",
                                             'x-redlock-auth': token},
                                         verify=False)

                        if repl.status_code == 200:
                            isOk = True
                            status = repl.json().get("attributes").get("status")

                            if status != "processing":
                                isReady = True
                                break

                    if isReady and isOk:
                        # get scan results and write to file
                        repl = requests.get(url=f"{prismaUrl}/iac/v2/scans/{assetId}/results",
                                            headers={
                                                'content-type': "application/vnd.api+json",
                                                'x-redlock-auth': token},
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
                else:
                    print("bad scan start")
                    raise BaseException("bad scan start")
            else:
                print("bad add asset")
                raise BaseException("bad add asset")
        else:
            print("bad login")
            raise BaseException("bad login")
    except BaseException as ex:
        print(ex)
        with open("res.txt", "w") as f:
            f.write(ex.__str__())
        GlobalOk = False
    finally:
        send_mail(f"alert from TC", YA_HOST, SENDER, YA_USER, YA_USER, YA_PASSWORD, "res.txt")
        if not GlobalOk:
            exit(666)
