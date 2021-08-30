import os

if __name__ == "__main__":
    lst = ['Python', 'Machine Learning', 'R Language', 'Bootstrap', 'Test']
    with open("check_res.txt", "w") as f:
        for x in lst:
            print(x)
            f.write(x)
        print("image size: ", os.path.getsize("tc_test.tar"))
        f.write(f"{os.path.getsize('tc_test.tar')}")
