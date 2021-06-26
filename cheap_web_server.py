# coding: utf-8
from datetime import datetime
from logging import getLogger, StreamHandler, Formatter, DEBUG, log
from os import getcwd, path
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Thread


from pytz import timezone


logger = getLogger(__name__)
logger.setLevel(DEBUG)
logger.propagete = False

handler = StreamHandler()
handler.setLevel(DEBUG)
handler_formater = Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger.addHandler(handler)


class HttpErrorStautusCode(Exception):
    """HTTPステータスコードにおける特定の400, 500番台に該当するエラーコードに該当する"""
    pass


class BadRequestError(HttpErrorStautusCode):
    """400 Bad Reuqest Errorを示す例外クラス"""
    ERR_CODE = 400


class NotFoundError(HttpErrorStautusCode):
    """404 Not Foundを示す例外クラス"""
    ERR_CODE = 404


class MethodNotAllowedError(HttpErrorStautusCode):
    """405 Method Not Allowedを示す例外クラス"""
    ERR_CODE = 405


class HttpVersionNotSupportedError(HttpErrorStautusCode):
    """505 HTTP Version Not Supportedを示す例外クラス"""
    ERR_CODE = 505


class HttpRequestParser():
    """
    HTTPリクエストをパースして辞書形式のオブジェクトを作成する

    Attributes
    ----------
    http_request : bytes
        バイナリ形式のHTTPリクエストのデータ
    ALLOWED_METHODS : set of str
        利用を許可しているHTTPメソッド名の集合で,現在はGETとHEADのみ対応
    ALLOWED_VERSIONS : set of str
        利用を許可しているHTTPプロトコルバージョンの集合
    ALLOWED_HEADERS : set of str
        送信を許可しているHTTPヘッダ名の集合
    """
    ALLOWED_METHODS = ("GET", "HEAD")
    ALLOWED_VERSIONS = ("1.0", "1.1")

    def __init__(self, http_request):
        self.http_request = http_request

    def parse_http_request(self):
        """
        送信されてきたHTTPリクエストをパースして各種データを格納した辞書を作成して返す

        Parameters
        ----------
        http_request : bytes
            送信されてきたHTTPリクエストのバイナリデータを想定

        Raises
        ------
        BadRequestError
            HTTPリクエストをUTF-8でデコード出来なかった場合

        Notes
        -----
        呼び出しているparse_request_line(), parse_request_headers()内において例外が
        発生する可能性がある

        Returns
        -------
        パースされたHTTPレスポンス : dict
        """
        try:
            decoded_http_request = self.http_request.decode("utf-8")
        except UnicodeDecodeError:
            logger.error("can't decode http request with utf-8.")
            raise BadRequestError()

        logger.debug("----- HTTP Request -----")
        logger.debug(decoded_http_request)

        splited_http_request = decoded_http_request.split('\r\n')

        # プロトコルバージョンが無い場合はHTTP0.9が利用されていると判断し,
        # request_lineのみを持つ辞書オブジェクトを返す
        request_line = self.parse_request_line(splited_http_request[0])
        if "protocol_version" not in request_line.keys():
            return {
                "request_line": request_line
            }

        # リクエストヘッダのスライスを取得してヘッダ名: 値の辞書を取得する
        empty_line_number = splited_http_request.index("")
        request_headers = self.parse_request_headers(
            splited_http_request[1:empty_line_number])

        # Content-Lengthが無い場合はリクエストボディを確認する必要が無い
        if "Content-Length" not in request_headers.keys():
            return {
                "request_line": request_line,
                "request_headers": request_headers,
                "body": ""
            }

        # Content-Lengthで指定された文字列分をボディとして取得して返す
        content_length = request_headers["Content-Length"]
        request_body = "".join(request_headers[empty_line_number:])
        return {
            "request_line": request_line,
            "request_headers": request_headers,
            "body": request_body[:content_length]
        }

    def parse_request_line(self, request_line):
        """
        HTTPリクエストラインをメソッド,URI,バージョンに分割して辞書形式にして返す

        Parameters
        ----------
        request_line : str
            文字列型のHTTPリクエストライン

        Raises
        ------
        BadRequestError
            request_lineをスペースで3つの要素に分割出来ない場合
            プロトコルバージョンがHTTP/からはじまっていない場合
        MethodNotAllowdError
            許可しているメソッドの集合であるLLOWED_METHODS内に存在しないメソッドが利用
            されている場合
        HttpVersionNotSupportedError
            許可されているプロトコルバージョンの集合であるALLOWED_VERSIONS内に存在しない
            プロトコルバージョンが利用されている場合

        Returns
        -------
        メソッド名, URI, プロトコルバージョンを格納している辞書 : dict
        """
        # メソッド, URI, バージョンの三要素に分割する事が出来なければ400に該当する例外を発生
        splited_request_line = request_line.split(' ')
        if len(splited_request_line) < 2:
            logger.error("parse_request_line: failed parse request line")
            raise BadRequestError()

        # 許可されていないHTTPメソッドが利用された場合は405に該当する例外を発生
        method = splited_request_line[0]
        if method not in self.ALLOWED_METHODS:
            logger.error("parse_request_line: use not allowed method")
            raise MethodNotAllowedError()

        uri = splited_request_line[1]

        # プロトコルバージョンが指定されていない場合はHTTP0.9を利用していると判断して
        # URIとメソッドのみを格納した辞書オブジェクトを返す
        if len(splited_request_line) == 2:
            return {
                "method": method,
                "uri": uri
            }

        # プロトコルバージョンがHTTP/から始まっていない場合は400に該当する例外を発生
        try:
            protocol_version = (splited_request_line[2]).split("HTTP/")[1]
        except IndexError:
            logger.error(
                "parse_request_line: protocol version isn't start witdh HTTP/."
            )
            raise BadRequestError()

        # 対応していないHTTPバージョンが利用された場合は505に該当する例外を発生
        if protocol_version not in self.ALLOWED_VERSIONS:
            logger.error(
                "parse_request_line: use not allowed protocol version"
            )
            raise HttpVersionNotSupportedError()

        return {
            "method": method,
            "uri": uri,
            "protocol_version": protocol_version
        }

    def parse_request_headers(self, request_headers):
        """
        文字列リストのHTTPリクエストヘッダを{ヘッダ名:ヘッダ値}の辞書形式にパースする

        Parameters
        ----------
        request_headers : list of str
            文字列の各HTTPリクエストヘッダを格納しているリスト

        Raises
        ------
        BadRequestError
            リクエストヘッダを : で分割する事が出来ない場合は誤った構文として判定

        Returns
        -------
        辞書形式のHTTPリクエストヘッダ : dict
            {ヘッダ名:ヘッダ値}の辞書
        """
        request_headers_dict = {}

        for request_header in request_headers:
            try:
                splited_request_header = request_header.split(': ')
                request_headers_dict[splited_request_header[0]] = \
                    ''.join(splited_request_header[1:])
            except IndexError:
                logger.error(
                    "parse_request_headers: request header is not split with :"
                    )
                raise BadRequestError()

        return request_headers_dict


class HttpResponseBuilder():
    """
    HTTPレスポンスを作成する

    Attributes
    ----------
    ROOT_DIRECTORY : str
        リソースを配置するトップディレクトリ
    http_request_dict : dict
        HTTPリクエストのリクエストライン・リクエストヘッダ・ボディが格納されている
    """
    ROOT_DIRECTORY = getcwd() + "/"

    def __init__(self, http_request):
        self.http_request = http_request
        self.http_request_dict = {}

    def build_http_response(self):
        """
        HTTPリクエストに対するHTTPレスポンスを構築して返す

        Notes
        -----
        エラーが発生した場合はbuild_http_response_with_error()メソッドでHTTPレスポンス
        を構築して返す

        Returns
        -------
        文字列形式のHTTPレスポンス
        """
        # HTTPリクエストをパースする
        http_request_parser = HttpRequestParser(self.http_request)
        try:
            self.http_request_dict = http_request_parser.parse_http_request()
        except HttpErrorStautusCode as err:
            # パースに失敗した場合は発生したエラーコードをセットしてHTTPレスポンスを構築
            logger.error("{}".format(err.ERR_CODE))
            return self.build_http_response_with_error(err.ERR_CODE)

        # パースされたHTTPリクエストライン内にrequest_headersが無ければHTTP0.9が利用され
        # ていると判断して,専用のHTTPレスポンス構築関数の返り値を返す様にする
        if "request_headers" not in self.http_request_dict.keys():
            return self.build_http_09_response()

        # 各HTTPメソッド毎のHTTPレスポンスを構築する関数を取得して実行する
        http_request_method = self.http_request_dict["request_line"]["method"]
        create_http_response_method = getattr(
            self, http_request_method.lower()
        )
        try:
            return create_http_response_method()
        except HttpErrorStautusCode as err:
            # HTTPレスポンスの構築中に失敗した場合は発生したエラーコードをセットして
            # HTTPレスポンスを構築
            logger.error("{}".format(err.ERR_CODE))
            return self.build_http_response_with_error(err.ERR_CODE)

    def extract_content_type(self, uri):
        """
        ファイルの拡張子からContent-Typeを判定して返す

        Parameters
        ----------
        uri : str
            HTTPリクエストラインで指定されているURI

        Notes
        -----
        .html : text/html
        .png : image/png
        それ以外: text/pain

        Returns
        -------
        Content-Typeにセットするための文字列
        """
        extention_type_dict = {
            ".txt": "text/plain",
            ".html": "text/html",
            ".css": "text/css",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gig",
            ".js": "application/javascript"
        }

        file_extension = path.splitext(uri)[1]
        try:
            return extention_type_dict[file_extension]
        except KeyError:
            return "text/plain"

    def build_abosolute_uri_path(self):
        """URIで指定されたリソースの絶対パスを構築して返す"""
        uri_basename = path.basename(
            self.http_request_dict["request_line"]["uri"]
        )
        return self.ROOT_DIRECTORY + uri_basename

    def load_uri_resource(self, absolute_uri):
        """
        URIで指定されたリソースの内容を読み込んで返す

        Parameters
        ----------
        uri_path : str

        Raises
        ------
        URIで指定されたリソースが存在しない場合はIOErrorを発生させる
        """
        try:
            with open(absolute_uri, "rb") as resource_file:
                resource_data = resource_file.read()
        except IOError:
            raise NotFoundError()

        return resource_data

    def build_http_response_line(self, statuscode):
        """
        HTTPレスポンスのレスポンスラインを構築して返す

        Returns
        -------
        HTTPレスポンスのレスポンスライン : str

        Notes
        -----
        該当するエラーコードがない場合は418を返す
        """
        statuscode_message = {
            200: "Ok",
            400: "Bad Reuqest Error",
            404: "Not Found",
            405: "Method Not Allowed",
            505: "HTTP Version Not Supported"
        }
        try:
            http_response_line = "HTTP/{} {} {}\r\n".format(
                self.http_request_dict["request_line"]["protocol_version"],
                statuscode, statuscode_message[statuscode]
                )
        except KeyError:
            http_response_line = "HTTP/{} 418 I'm a teapot\r\n".format(
                self.http_request_dict["request_line"]["protocol_version"]
                )
        return http_response_line

    def build_get_head_http_response_headers(self, body):
        """
        GET, HEADに対応するHTTPレスポンスのレスポンスヘッダを構築して返す

        Returns
        -------
        HTTPヘッダ : str

        Notes
        -----
        Content-Length, Content-Type, Connection, Date, Serverのみに対応する
        """
        uri = self.http_request_dict["request_line"]["uri"]

        http_headers = ""
        http_headers += "Content-Length: {}\r\n".format(len(body))
        http_headers += "Content-Type: {}\r\n".format(
            self.extract_content_type(uri)
        )
        http_headers += "Connection: close\r\n"
        current_date = datetime.now(timezone("UTC"))
        http_headers += "Date: {} GMT\r\n".format(
            current_date.strftime("%b, %d %m %Y %H:%M:%S")
        )
        http_headers += "Server: {}\r\n".format("cheap http server")

        return http_headers

    def get(self):
        """
        GETリクエストに対するHTTPレスポンスを構築して返す

        Returns
        -------
        文字列形式のHTTPレスポンス
        """
        absolute_uri = self.build_abosolute_uri_path()

        body = self.load_uri_resource(absolute_uri)

        http_response = ""
        http_response += self.build_http_response_line(200)
        http_response += self.build_get_head_http_response_headers(
            body
        )
        http_response += "\r\n"

        http_response = bytes(http_response, encoding="utf-8")
        http_response += body

        return http_response

    def head(self):
        """
        HEADリクエストに対するHTTPレスポンスを構築して返す

        Returns
        -------
        文字列形式のHTTPレスポンス
        """
        absolute_uri = self.build_abosolute_uri_path()

        body = self.load_uri_resource(absolute_uri)

        http_response = ""
        http_response += self.build_http_response_line(200)
        http_response += self.build_get_head_http_response_headers(
            body
        )

        http_response = bytes(http_response, encoding="utf-8")

        return http_response

    def build_http_09_response(self):
        """
        HTTP0.9を利用したHTTPリクエストを構築して返す

        Notes
        -----
        load_uri_resourceを利用してURIで指定されたリソースを取得して返す
        """
        absolute_uri = self.build_abosolute_uri_path()

        http_response = self.load_uri_resource(absolute_uri)

        return bytes(http_response, encoding="utf-8")

    def build_http_response_with_error(self, err_code):
        """
        HTTPレスポンスを構築する段階でエラーが発生した場合のHTTPレスポンスを構築して返す

        Parametes
        ---------
        err_code : str
            発生したエラーコード

        Returns
        -------
        文字列形式のHTTPレスポンス
        """
        http_response = ""
        http_response += self.build_http_response_line(err_code)
        http_response += "Connection: close\r\n"
        current_date = datetime.now(timezone("UTC"))
        http_response += "Date: {} GMT\r\n".format(
            current_date.strftime("%b, %d %m %Y %H:%M:%S")
        )
        http_response += "Server: {}\r\n".format("cheap http server")

        return bytes(http_response, encoding="utf-8")


class HttpRequestHandler():
    """
    HTTPリクエストを処理する機能を提供する

    Attributes
    ----------
    MAX_HTTP_REQUEST_SIZE : int
        1度のHTTPリクエストとして許可する最大サイズ
    client_socket : socket object
        アクセスして来たクライアントのソケット
    request_dist : dict
        HTTPリクエストに含まれる各要素を格納している辞書
    """
    MAX_HTTP_REQUEST_SIZE = 8192

    def __init__(self, client_socket):
        self.client_socket = client_socket
        self.request_dict = {}

    def handle_http_request(self):
        """
        HTTPリクエストの受信からHTTPレスポンスの送信の一連の流れを行う
        """
        # HTTPリクエストを受信
        http_request = self.client_socket.recv(self.MAX_HTTP_REQUEST_SIZE)

        # HTTPリクエストに対応するHTTPレスポンスを構築する
        http_response_builder = HttpResponseBuilder(http_request)
        http_response = http_response_builder.build_http_response()

        # 作成したHTTPレスポンスを返す
        self.send_http_request(http_response)

        # クライアントソケットをクローズ
        self.client_socket.close()

    def send_http_request(self, http_response):
        """
        クライアントソケットを介してHTTPレスポンスを送信する

        Parameters
        ----------
        http_response : bytes
            HTTPレスポンス
        """
        logger.debug("----- HTTP Response -----")
        logger.debug(http_response.decode("utf-8", "ignore"))
        self.client_socket.send(http_response)


class HttpServer():
    """
    単純なHTTPサーバ

    Attirbutes
    ----------
    addr : str
        サーバをバインドするIPアドレス
    port : int
        サーバをポートするIPアドレス
    max_listen_number : int
        最大接続数
    server_socket : socket object
        サーバソケット
    """

    def __init__(self, addr, port, max_listen_number):
        self.addr = addr
        self.port = port
        self.max_listen_number = max_listen_number
        self.server_socket = socket(AF_INET, SOCK_STREAM)

    def start_server(self):
        """
        サーバソケットの設定を行い,接続が来た場合は各クライアントにおいてやり取りを行う
        """

        # TIME_WAIT対策でSO_REUSEADDRを有効にする
        self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.server_socket.bind((self.addr, self.port))
        self.server_socket.listen(self.max_listen_number)

        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                request_handler = HttpRequestHandler(client_socket)
                handle_request_thread = Thread(target=request_handler.handle_http_request, args=())
                handle_request_thread.start()
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    server = HttpServer("127.0.0.1", 8000, 5)
    server.start_server()
