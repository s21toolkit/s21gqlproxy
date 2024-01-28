from mitmproxy import http
from os import getenv
from pathlib import Path
from json import dumps, loads
import logging

class GQLHarLogEntry:
	def __init__(self, opName: str, query: str, response: str) -> None:
		self.query = query
		self.response = response
		self.opName = opName

	def save(self, folder: Path) -> None:
		folder.joinpath(f'{self.opName}.har').write_text(self.__str__())

	def __str__(self):
		return dumps({
			'log': {
				'entries': [{
					'request': {
						'cookies': {},
						'headers': [],
						'postData': {
							'text': self.query,
						}
					},
					'response': {
						'cookies': {},
						'headers': [],
						'content': {
							'text': self.response,
						}
					}
				}]
			}
		}, indent=2)

class Extractor:
	def __init__(self):
		self.ROOT_DIR = Path(getenv('HOME') or '~', '.mitmproxy', 'dump')
		self.QUERIES_DIR = Path(self.ROOT_DIR, 'queries')
		self.MUTATIONS_DIR = Path(self.ROOT_DIR, 'mutations')

		self.QUERIES = set()
		self.MUTATIONS = set()

		for e in self.QUERIES_DIR.iterdir():
			self.MUTATIONS.add(e.name.split('.')[0])
		for e in self.MUTATIONS_DIR.iterdir():
			self.MUTATIONS.add(e.name.split('.')[0])

		self.ROOT_DIR.mkdir(exist_ok=True)
		self.QUERIES_DIR.mkdir(exist_ok=True)
		self.MUTATIONS_DIR.mkdir(exist_ok=True)
		

	def response(self, flow: http.HTTPFlow):
		if flow.request.url.endswith('/services/graphql'):
			if flow.request.content and flow.response and flow.response.content:
				rawReq = flow.request.content.decode()
				req = loads(rawReq)


				res = flow.response.content.decode()
				if req['query'].startswith('query') and not req['operationName'] in self.QUERIES:
					self.QUERIES.add(req['operationName'])
					GQLHarLogEntry(req['operationName'], rawReq, res).save(self.QUERIES_DIR)
				elif req['query'].startswith('mutation') and not req['operationName'] in self.MUTATIONS:
					self.MUTATIONS.add(req['operationName'])
					GQLHarLogEntry(req['operationName'], rawReq, res).save(self.MUTATIONS_DIR)
		elif flow.request.url.endswith('/static.js'):
				if flow.request.raw_content:
					self.ROOT_DIR.joinpath('static.js').write_bytes(flow.request.raw_content)



addons = [Extractor()]