import web
import hmacsha1

urls = (
    '/test', 'FileHandler'
)
app = web.application(urls, globals())


class FileHandler:

    def GET(self):
        params = web.input()
        if params.file:
            print('hi')
        if params.signature:
            print('oh')
        return params.file


def main():
    app.run()
    key = b'akd8wj3uajsmdkw8dkam'
    result = hmacsha1.insecure_compare(key, b'foo', b'0193463b5f82297d300b70de2dae3d9f13bfc668')
    print(result)


if __name__ == "__main__":
    main()
