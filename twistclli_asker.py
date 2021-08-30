import requests


if __name__ == "__main__":
    GlobalOk = True
    try:
        pass
    except BaseException as ex:
        print(ex)
        with open("res.txt", "w") as f:
            f.write(ex.__str__())
        GlobalOk = False
    finally:
        if not GlobalOk:
            exit(666)
