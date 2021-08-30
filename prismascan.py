import requests
from requests.auth import HTTPBasicAuth
import base64

from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

prismaUrl = "%prisma_url%"

# failureMask = {
#     "high": 1,
#     "medium": 10,
#     "low": 30,
#     "operator": "or"
# }
#
# filename = "check_res.txt"

prismaUser = "%prisma_user%"
prismaPass = "%prisma_psw%"

attemptNumber = 5
timeout = 2000

imagename = "%image_name%"
collection = "%collection%"

baseauth = HTTPBasicAuth(prismaUser, prismaPass)
b64_auth_str = base64.b64encode(bytes(f"{prismaUser}:{prismaPass}", "utf-8"))
auth_string = f'Basic {b64_auth_str.decode("utf-8")}'


# print(f"{auth_string}")


def check_code(code, mustbe, ex):
    if code != mustbe:
        print(code, mustbe)
        raise BaseException(ex)


if __name__ == "__main__":
    GlobalOk = True
    try:
        # # login
        # repl = requests.post(url=f"{prismaUrl}/api/v1/authenticate",
        #                      json={
        #                          "username": prismaUser,
        #                          "password": prismaPass,
        #                      },
        #                      headers={
        #                          'content-type': "application/json",
        #                          "Authorization": auth_string,
        #                      },
        #                      auth=baseauth,
        #                      verify=False)
        #
        # # #################################################
        # check_code(repl.status_code, 200, "bad login")
        # # #################################################
        #
        # print("ok login")
        #
        # token = repl.json().get("token")
        # print(token)

        # names
        repl = requests.get(url=f"{prismaUrl}/api/v1/images/names",
                            # json={
                            #     "imageTag": {
                            #         "digest": "c9e838fce140",
                            #         "id": "d9a6f1c5611b",
                            #         "registry": "hub.docker.com",
                            #         "repo": "russub10",
                            #         "tag": "latest"
                            #     }
                            # },
                            headers={
                                'content-type': "application/json",
                                # "x-redlock-auth": token,
                                "Authorization": auth_string,
                            },
                            auth=baseauth,
                            verify=False)

        names_list = repl.json()
        print("repl get names:", "\n".join(names_list))

        # #################################################
        check_code(repl.status_code, 200, "bad get names")
        # #################################################

        # go scan
        repl = requests.post(
            url=f"{prismaUrl}/api/v1/images/scan?imageID=sha256:{'d9a6f1c5611bc6c0759334c1a54fffa1e5929039faf857acb853114ded155cd7'}",
            json={
                # "imageTag": {
                #     "digest": "c9e838fce140",
                #     #"id": "d9a6f1c5611b",
                #     "id": "sha256:d9a6f1c5611bc6c0759334c1a54fffa1e5929039faf857acb853114ded155cd7",
                #     "registry": "unix:///var/run/docker.sock",
                #     "repo": "russub10",
                #     "tag": "latest"
                # },
                "hostname": "worker-1",
                "imageTag": {
                    "digest": "c9e838fce140",
                    #"digest": "sha256:c9e838fce140d6ba77a4a194e388b5093572fc2509fa8dad626c6102b9de8224",
                    # "id": "d9a6f1c5611b",
                    "id": "sha256:d9a6f1c5611bc6c0759334c1a54fffa1e5929039faf857acb853114ded155cd7",
                    #"registry": "",
                    "repo": "russub10/malware4",
                    #"tag": "latest"
                }
                # "imageTag": {
                #     # "digest": "c9e838fce140",
                #     "digest": "sha256:0c48c6d19aa7f4742c70a28cf10977949fcde06093a50490c03676ddec577fb1",
                #     # "id": "d9a6f1c5611b",
                #     "id": "sha256:61ed796ee386eaa02c0d64ce7ca0abcd751a2b0307bf89459884548b2d1432d2",
                #     # "registry": "hub.docker.com",
                #     "repo": "jetbrains",
                #     "tag": "latest"
                # }
            },
            headers={
                'content-type': "application/json",
                # "x-redlock-auth": token,
                "Authorization": auth_string,
            },
            auth=baseauth,
            verify=False)

        print("repl start scan:", repl.content)

        # #################################################
        check_code(repl.status_code, 200, "bad scan")
        # #################################################

        # get progress
        repl = requests.get(
            url=f"{prismaUrl}/api/v1/images/progress?imageID=sha256:{'d9a6f1c5611bc6c0759334c1a54fffa1e5929039faf857acb853114ded155cd7'}",
            # json={
            #     "imageTag": {
            #         "digest": "c9e838fce140",
            #         "id": "d9a6f1c5611b",
            #         "registry": "hub.docker.com",
            #         "repo": "russub10",
            #         "tag": "latest"
            #     }
            # },
            headers={
                'content-type': "application/json",
                # "x-redlock-auth": token,
                "Authorization": auth_string,
            },
            auth=baseauth,
            verify=False)

        print("repl get progress:", repl.content)

        # #################################################
        check_code(repl.status_code, 200, "bad get progress")
        # #################################################

        # go get res
        repl = requests.get(
            url=f"{prismaUrl}/api/v1/scans?imageID=sha256:{'d9a6f1c5611bc6c0759334c1a54fffa1e5929039faf857acb853114ded155cd7'}",
            # json={
            #     "imageTag": {
            #         # "digest": "string",
            #         "id": "d9a6f1c5611b",
            #         # "registry": "string",
            #         # "repo": "string",
            #         "tag": "latest"
            #     }
            # },
            headers={
                'content-type': "application/json",
                # "x-redlock-auth": token,
                "Authorization": auth_string,
            },
            auth=baseauth,
            verify=False)

        scres = repl.json()
        print("repl scan res:", scres)

        for el in scres:
            el["entityInfo"]["binaries"] = []
            el["entityInfo"]["startupBinaries"] = []
            el["entityInfo"]["packages"] = []
            el["entityInfo"]["applications"] = []
            el["entityInfo"]["history"] = []
            el["entityInfo"]["complianceIssues"] = []
            el["entityInfo"]["allCompliance"] = []
            el["entityInfo"]["vulnerabilities"] = []
            print("repl scan res:", el.get("entityInfo"))

        # #################################################
        check_code(repl.status_code, 200, "bad get res")
        # #################################################

        # # go add
        # repl = requests.post(
        #     url=f"{prismaUrl}/api/v1/scans?imageID=sha256:{'d9a6f1c5611bc6c0759334c1a54fffa1e5929039faf857acb853114ded155cd7'}",
        #     json=repl.json(),
        #     headers={
        #         'content-type': "application/json",
        #         # "x-redlock-auth": token,
        #         "Authorization": auth_string,
        #     },
        #     auth=baseauth,
        #     verify=False)

        # print("repl add:", repl.json())

        # # #################################################
        # check_code(repl.status_code, 200, "bad add")
        # # #################################################
    except BaseException as ex:
        print(ex)
        with open("res.txt", "w") as f:
            f.write(ex.__str__())
        GlobalOk = False
    finally:
        if not GlobalOk:
            exit(666)
