import contextlib
import http.client
import io
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from linuxhound.cli import main
from linuxhound.serve import make_server


class ViewerServerTests(unittest.TestCase):
    def test_only_tokened_html_is_served(self):
        with tempfile.TemporaryDirectory() as directory:
            html = Path(directory) / 'index.html'
            html.write_text('<html>Selected viewer</html>')
            (Path(directory) / 'report.json').write_text('private evidence')
            with make_server(html, port=0) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                token_path = '/' + server.viewer_url.split('/', 3)[3]
                def request(path, method='GET', host=None):
                    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                    connection.request(method, path, headers={'Host': host} if host else {})
                    response = connection.getresponse()
                    result = response.status, response.read(), dict(response.getheaders())
                    connection.close()
                    return result
                try:
                    status, body, headers = request(token_path)
                    self.assertEqual(status, 200)
                    self.assertIn(b'Selected viewer', body)
                    self.assertEqual(headers['Cache-Control'], 'no-store')
                    self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
                    self.assertEqual(request(token_path, 'HEAD')[1], b'')
                    for path in ('/', '/index.html', '/report.json', token_path+'report.json',
                                 token_path+'../report.json', '/%2e%2e/report.json', token_path+'?token=other'):
                        status, body, _ = request(path)
                        self.assertEqual(status, 404, path)
                        self.assertNotIn(b'private evidence', body)
                    self.assertEqual(request(token_path, host='attacker.example')[0], 421)
                finally:
                    server.shutdown()
                    thread.join(timeout=3)

    def test_invalid_source_and_address_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'index.html'
            target.write_text('viewer')
            link = Path(directory) / 'link.html'
            link.symlink_to(target)
            for path in (link, Path(directory)/'report.json'):
                with self.assertRaises(ValueError):
                    make_server(path, port=0)
            with self.assertRaises(ValueError):
                make_server(target, listen='example.com', port=0)
            with self.assertRaises(ValueError):
                make_server(target, port=99999)

    def test_cli_demo_passes_explicit_server_options(self):
        with tempfile.TemporaryDirectory() as directory, patch('linuxhound.serve.serve_viewer') as serve:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['demo', '--output-dir', directory, '--serve', '--open', '--port', '9000']), 0)
            path, listen, port, opened = serve.call_args.args
            self.assertTrue(Path(path).is_file())
            self.assertEqual((listen, port, opened), ('127.0.0.1', 9000, True))


if __name__ == '__main__':
    unittest.main()
