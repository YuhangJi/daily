import re
import time
import argparse
import requests
from hmac import new
from hashlib import md5, sha1


class BuceaNet(object):

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.sess = requests.session()
        self.header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/86.0.4240.111 Safari/537.36 "
        }
        self.CHALLENGE_API = "http://10.1.1.131/cgi-bin/get_challenge"
        self.SRUN_PORTAL_API = "http://10.1.1.131/cgi-bin/srun_portal"
        self.ROOT_URL = "http://10.1.1.131"

        self.ip = self.__get_ip()
        self.token = self.__get_token()
        self.ac_id = '1'
        self.enc = "srun_bx1"
        self.n = "200"
        self.type = "1"

        self.info = self.__get_info()
        self.hmd5 = self.__get_md5()
        self.chksum = self.__get_chksum()

        self.srun_portal_params = {
            'callback': 'jQuery11240645308969735664_' + str(int(time.time() * 1000)),
            'action': 'login',
            'username': self.username,
            'password': '{MD5}' + self.hmd5,
            'ac_id': self.ac_id,
            'ip': self.ip,
            'chksum': self.chksum,
            'info': self.info,
            'n': self.n,
            'type': self.type,
            'os': 'windows+10',
            'name': 'windows',
            'double_stack': '0',
            '_': int(time.time() * 1000)
        }

    def login(self):
        srun_portal_res = self.sess.post(self.SRUN_PORTAL_API,data=self.srun_portal_params,headers=self.header)

        if re.search("E0000", srun_portal_res.text):
            print("Login Success.")
        elif re.search("ip_already_online_error", srun_portal_res.text):
            print("already online, client_ip is: {}".format(self.ip))
        else:
            print("Login Failed.")

    def __get_ip(self):
        init_res = self.sess.get(self.ROOT_URL, headers=self.header)
        return re.search('ip(\s*):(\s*)"(.*)"', init_res.text).group(3)

    def __get_token(self):
        get_challenge_params = {
            "callback": "jQuery112404953340710317169_" + str(int(time.time() * 1000)),
            "username": self.username,
            "ip": self.ip,
            "_": int(time.time() * 1000),
        }
        get_challenge_res = requests.get(
            self.CHALLENGE_API, params=get_challenge_params, headers=self.header
        )
        return re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)

    def __get_info(self):
        info_temp = {
            "username": self.username,
            "password": self.password,
            "ip": self.ip,
            "acid": self.ac_id,
            "enc_ver": self.enc,
        }
        info = re.sub("'", '"', str(info_temp))
        info = re.sub(" ", "", info)
        info = "{SRBX1}" + self.__get_base64(self.__get_xencode(info, self.token))
        return info

    def __get_md5(self):
        return new(self.token.encode(), self.password.encode(), md5).hexdigest()

    def __get_chksum(self):
        chkstr = self.token + self.username
        chkstr += self.token + self.hmd5
        chkstr += self.token + self.ac_id
        chkstr += self.token + self.ip
        chkstr += self.token + self.n
        chkstr += self.token + self.type
        chkstr += self.token + self.info
        return sha1(chkstr.encode()).hexdigest()

    @staticmethod
    def __get_base64(s):
        _PADCHAR = "="
        _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
        i = 0
        b10 = 0
        x = []
        imax = len(s) - len(s) % 3

        def get_byte(s_,i_):
            return ord(s_[i_])

        if len(s) == 0:
            return s
        for i in range(0, imax, 3):
            b10 = (
                    (get_byte(s, i) << 16) | (get_byte(s, i + 1) << 8) | get_byte(s, i + 2)
            )
            x.append(_ALPHA[(b10 >> 18)])
            x.append(_ALPHA[((b10 >> 12) & 63)])
            x.append(_ALPHA[((b10 >> 6) & 63)])
            x.append(_ALPHA[(b10 & 63)])
        i = imax
        if len(s) - imax == 1:
            b10 = get_byte(s, i) << 16
            x.append(
                _ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR
            )
        elif len(s) - imax == 2:
            b10 = (get_byte(s, i) << 16) | (get_byte(s, i + 1) << 8)
            x.append(
                _ALPHA[(b10 >> 18)]
                + _ALPHA[((b10 >> 12) & 63)]
                + _ALPHA[((b10 >> 6) & 63)]
                + _PADCHAR
            )
        return "".join(x)

    @staticmethod
    def __get_xencode(msg, key):
        from math import floor
        if msg == "":
            return ""

        def ordat(msg, idx):
            if len(msg) > idx:
                return ord(msg[idx])
            return 0

        def sencode(msg, key):
            l = len(msg)
            pwd = []
            for i in range(0, l, 4):
                pwd.append(
                    ordat(msg, i)
                    | ordat(msg, i + 1) << 8
                    | ordat(msg, i + 2) << 16
                    | ordat(msg, i + 3) << 24
                )
            if key:
                pwd.append(l)
            return pwd

        def lencode(msg, key):
            l = len(msg)
            ll = (l - 1) << 2
            if key:
                m = msg[l - 1]
                if m < ll - 3 or m > ll:
                    return
                ll = m
            for i in range(0, l):
                msg[i] = (
                        chr(msg[i] & 0xFF)
                        + chr(msg[i] >> 8 & 0xFF)
                        + chr(msg[i] >> 16 & 0xFF)
                        + chr(msg[i] >> 24 & 0xFF)
                )
            if key:
                return "".join(msg)[0:ll]
            return "".join(msg)
        pwd = sencode(msg, True)
        pwdk = sencode(key, False)
        if len(pwdk) < 4:
            pwdk = pwdk + [0] * (4 - len(pwdk))
        n = len(pwd) - 1
        z = pwd[n]
        y = pwd[0]
        c = 0x86014019 | 0x183639A0
        m = 0
        e = 0
        p = 0
        q = floor(6 + 52 / (n + 1))
        d = 0
        while 0 < q:
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = d >> 2 & 3
            p = 0
            while p < n:
                y = pwd[p + 1]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (pwdk[(p & 3) ^ e] ^ z)
                pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = pwd[p]
                p = p + 1
            y = pwd[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
            z = pwd[n]
            q = q - 1
        return lencode(pwd, False)

    def __del__(self):
        self.sess.close()


if __name__ == '__main__':
    # load parameters from command line
    parser = argparse.ArgumentParser(prog="bucealoginner")
    parser.add_argument('--username',type=str, default='123')
    parser.add_argument('--password',type=str, default='123')
    __args = parser.parse_args()
    # <<<
    BuceaNet(__args.username,__args.password).login()
