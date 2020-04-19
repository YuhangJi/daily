# -*- coding: utf-8 -*-
import time
import random
import argparse
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar


class BuceaLoginner:
    """
    2020年4月18日
    """

    url_dict = {"get_url": "http://10.1.1.131:903/srun_portal_pc.php?ac_id=1&",
                "post_url": "http://10.1.1.131:903/srun_portal_pc.php?ac_id=1&url=www.msftconnecttest.com"}
    ua_list = [
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/78.0.3904.108 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/79.0.3945.88 Safari/537.36 ",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"]

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def __init__(self, user_name=None, pass_word=None,
                 start_time=1, end_time=5):

        self.__ps = {"user_name": user_name,  # ps <=> parameters dictionary
                     "pass_word": pass_word,
                     "start_time": start_time,
                     "end_time": end_time}

    @staticmethod
    def _get_time():
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    @staticmethod
    def _get_content_length(data):
        length = len(data.keys()) * 2 - 1
        total = ''.join(list(data.keys()) + list(data.values()))
        length += len(total)
        return length

    def _get_ua(self):
        random.shuffle(self.ua_list)
        return self.ua_list[0]

    def down_time(self):
        hour = int(self._get_time().split(" ")[-1].split(":")[0])
        if self.__ps["start_time"] <= hour < self.__ps["end_time"]:
            return True
        else:
            return False

    def bucea_login(self):
        state_code = {200: "Success to connect!", 400: "Connection has been failed!", 0: "unknown"}
        ua = self._get_ua()  # user-agent
        get_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Host': '10.1.1.131:903',
            'Referer': 'http://10.1.1.131/index_1.html',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': ua}

        try:
            req = urllib.request.Request(url=self.url_dict["get_url"],
                                         headers=get_headers)
            self.opener.open(req)
        except TimeoutError:
            print(self._get_time(), "Program raised a TimeoutError with the long waiting time.")
        except urllib.error.HTTPError as e:
            print(self._get_time(), "HTTPError:{}".format(e.code))
        except urllib.error.URLError as e:
            print(self._get_time(), e.reason)

        data_dict = {
            'action': 'login',
            'ac_id': '1',
            'user_ip': '',
            'nas_ip': '',
            'user_mac': '',
            'url': '',
            'username': self.__ps["user_name"],
            'password': self.__ps["pass_word"]}

        content_length = str(self._get_content_length(data_dict))  # content_length

        post_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Content-Length': content_length,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': '10.1.1.131:903',
            'Origin': 'http://10.1.1.131:903',
            'Referer': 'http://10.1.1.131:903/srun_portal_pc.php?ac_id=1&url=www.msftconnecttest.com',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': ua}
        form_data = urllib.parse.urlencode(data_dict).encode(encoding='utf-8')  # encode post data
        code = 0

        try:
            request = urllib.request.Request(url=self.url_dict["post_url"],
                                             data=form_data,
                                             headers=post_headers)
            response = self.opener.open(request)
            if response.getcode() == 200:
                code = response.getcode()
        except TimeoutError:
            print(self._get_time(), "TimeoutError")
            code = 400
        except urllib.error.HTTPError as e:
            print(self._get_time(), "HTTPError:{}".format(e.code))
            code = 400
        except urllib.error.URLError as e:
            print(self._get_time(), e.reason)
            code = 400
        finally:
            print(self._get_time(), state_code[code])
        return code


def main():
    # load parameters from command line
    parser = argparse.ArgumentParser(prog="bucealoginner")
    parser.add_argument('--username', default=None)
    parser.add_argument('--password', default=None)
    parser.add_argument('--delaytime', default=7200)
    parser.add_argument('--starttime', default=1)
    parser.add_argument('--endtime', default=5)
    parser.add_argument('--resttime', default=300)
    __args = parser.parse_args()
    # <<<

    # >>> checking parameters
    __user_name = __args.username
    if isinstance(__user_name, str):
        button = False
        for _ in __user_name:
            if _ not in [str(__) for __ in range(10)]: button = True
        if button:
            raise ValueError("Non-number included in parameter.[{}]".format("username"))
    elif __user_name is None:
        raise ValueError("Please input the important parameter .[{}]".format("username"))
    elif isinstance(__user_name, int):
        __user_name = str(__user_name)
    else:
        raise ValueError("Unknown parameter .[{}]".format("username"))

    __pass_word = __args.password
    if isinstance(__pass_word, str):
        pass
    elif isinstance(__pass_word, int):
        __pass_word = str(__pass_word)
    elif __pass_word is None:
        raise ValueError("Please input the important parameter .[{}]".format("password"))
    else:
        raise ValueError("Unknown parameter .[{}]".format("password"))

    __delay_time = __args.delaytime
    if isinstance(__delay_time, str):
        __delay_time = float(__delay_time)
        __delay_time = int(__delay_time)
    __start_time = __args.starttime
    if isinstance(__start_time, str):
        __start_time = float(__start_time)
        __start_time = int(__start_time)
    __end_time = __args.endtime
    if isinstance(__end_time, str):
        __end_time = float(__end_time)
        __end_time = int(__end_time)
    if __end_time < __start_time:
        __tran = __start_time
        __start_time = __end_time
        __end_time = __tran
    __rest_time = __args.resttime
    if isinstance(__rest_time, str):
        __rest_time = float(__rest_time)
        __rest_time = int(__rest_time)
    # <<<

    # >>>  login loop
    loginner = BuceaLoginner(user_name=__user_name,
                             pass_word=__pass_word,
                             start_time=__start_time,
                             end_time=__end_time)
    while True:
        if loginner.down_time():
            time.sleep(__rest_time)
            continue
        try:
            loginner.bucea_login()
        except Exception:
            time.sleep(__rest_time)
            loginner.bucea_login()
        finally:
            time.sleep(__delay_time)
    # <<<


if __name__ == "__main__":
    main()
