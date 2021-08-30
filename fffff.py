import requests
from requests.auth import HTTPBasicAuth
import base64

# from urllib3.exceptions import InsecureRequestWarning

# requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

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

imagename = "%image_name%"

certpath = "%ssl_cert%"
keypath = "%ssl_key%"

baseauth = HTTPBasicAuth(prismaUser, prismaPass)
b64_auth_str = base64.b64encode(bytes(f"{prismaUser}:{prismaPass}", "utf-8"))
auth_string = f'Basic {b64_auth_str.decode("utf-8")}'


# print(f"{auth_string}")


def check_code(code, mustbe, ex):
    if code != mustbe:
        print(code, mustbe)
        raise BaseException(ex)


if __name__ == "__main__":
    # sess = requests.Session()
    # sess.verify = certpath

    cert = (certpath, keypath)

    GlobalOk = True
    try:
        # login
        repl = requests.post(url=f"{prismaUrl}/login",
                             json={
                                 "username": prismaUser,
                                 "password": prismaPass,
                             },
                             headers={
                                 "Accept": "application/vnd.api+json",
                                 'content-type': "application/vnd.api+json",
                                 # "Authorization": auth_string,
                             },
                             # auth=baseauth,
                             cert=cert,
                             # verify=False,
                             )

        # #################################################
        check_code(repl.status_code, 200, "bad login")
        # #################################################

        token = repl.json().get("token")
        print(token)
    except BaseException as ex:
        print(ex)
        with open("res.txt", "w") as f:
            f.write(ex.__str__())
        GlobalOk = False
    finally:
        if not GlobalOk:
            exit(666)
