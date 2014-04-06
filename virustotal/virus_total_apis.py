#!/usr/bin/python

"""Simple class to interact with VirusTotal's Public and Private API as well as VirusTotal Intelligence.

The APIs are documented at:
https://www.virustotal.com/en/documentation/public-api/
https://www.virustotal.com/en/documentation/private-api/
https://www.virustotal.com/intelligence/help/automation/

EXAMPLE USAGE:::

from virus_total_apis import PublicApi as vtPubAPI

vt = vtPubAPI(<INSERT_API_KEY_HERE>)
response = vt.get_file_report('44cda81782dc2a346abd7b2285530c5f')

print json.dumps(response, sort_keys=False, indent=4)

"""
__author__ = 'Josh Maine'
__version__ = '1'
__license__ = 'GPLv3'

import requests


class PublicApi():
    """ Whenever you exceed the public API request rate limit a 204 HTTP status code is returned.
     If you try to perform calls to functions for which you do not have the required privileges
     an HTTP Error 403 Forbidden is raised.
    """

    def __init__(self, api_key, proxies=None):
        self.api_key = api_key
        self.proxies = proxies
        self.base = 'https://www.virustotal.com/vtapi/v2/'
        self.version = 2

    def scan_file(self, this_file):
        """ Submit a file to be scanned by VirusTotal

        :param this_file: File to be scanned (32MB file size limit)
        :return:
        """
        params = {'apikey': self.api_key}
        files = {'file': (this_file, open(this_file, 'rb'))}

        try:
            response = requests.post(self.base + 'file/scan', file=files, params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def rescan_file(self, this_hash):
        """ Rescan a previously submitted filed or schedule an scan to be performed in the future.

        :param this_hash:
        :return:
        """
        params = {'apikey': self.api_key, 'hash': this_hash}

        try:
            response = requests.post(self.base + 'file/rescan', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_file_report(self, this_hash):
        """ Get the scan results for a file.

        You can also specify a CSV list made up of a combination of hashes and scan_ids
        (up to 4 items with the standard request rate), this allows you to perform a batch
        request with one single call.
        i.e. {'resource': '99017f6eebbac24f351415dd410d522d, 88817f6eebbac24f351415dd410d522d'}.

        :param this_hash:
        :return:
        """
        params = {'apikey': self.api_key, 'resource': this_hash}

        try:
            response = requests.get(self.base + 'file/report', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def scan_url(self, this_url):
        """ Submit a URL to be scanned by VirusTotal.

        :param this_url:
        :return:
        """
        params = {'apikey': self.api_key, 'url': this_url}

        try:
            response = requests.post(self.base + 'url/scan', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_url_report(self, this_url, scan='0'):
        """ Get the scan results for a URL. (can do batch searches like get_file_report)

        :param this_url:
        :param scan:
        :return:
        """
        params = {'apikey': self.api_key, 'resource': this_url, 'scan': scan}

        try:
            response = requests.get(self.base + 'url/report', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def put_comments(self, resource, comment):
        """ Post a comment on a file or URL.

        :param resource:
        :param comment:
        :return:
        """
        params = {'apikey': self.api_key, 'resource': resource, 'comment': comment}

        try:
            response = requests.post(self.base + 'comments/put', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_ip_report(self, this_ip):
        """ Get information about a given IP address.

        :param this_ip:
        :return:
        """
        params = {'apikey': self.api_key, 'ip': this_ip}

        try:
            response = requests.get(self.base + 'ip-address/report', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_domain_report(self, this_domain):
        """ Get information about a given domain.

        :param this_domain:
        :return:
        """
        params = {'apikey': self.api_key, 'domain': this_domain}

        try:
            response = requests.get(self.base + 'domain/report', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def handle_response_status_code(self, this_response):
        if this_response.status_code == 203:
            return "ERROR: You exceed the public API request rate limit (4 requests of any nature per minute)"
        if this_response.status_code == 403:
            return "ERROR: You tried to perform calls to functions for which you require a Private API key."
        if this_response.status_code == requests.codes.ok:
            return False


class PrivateApi(PublicApi):
    def scan_file(self, this_file, notify_url='', notify_changes_only=''):
        """ Submit a file to be scanned by VirusTotal.

        :param this_file:
        :param notify_url:
        :param notify_changes_only:
        :return:
        """
        params = {'apikey': self.api_key}
        files = {'file': (this_file, open(this_file, 'rb'))}

        try:
            response = requests.post(self.base + 'file/scan', file=files, params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    @property
    def get_upload_url(self):
        """ Get a special URL for submitted files bigger than 32MB.

        In order to submit files bigger than 32MB you need to obtain a special upload URL to which you
        can POST files up to 200MB in size. This API generates such a URL.

        :return:
        """
        params = {'apikey': self.api_key}

        try:
            response = requests.get(self.base + 'file/scan/upload_url', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()['upload_url']
        else:
            return dict(response_code=response.status_code)

    def rescan_file(self, this_hash, date='', period='', repeat='', notify_url='', notify_changes_only=''):
        """ Rescan a previously submitted filed or schedule an scan to be performed in the future.

        This API allows you to rescan files present in VirusTotal's file store without having to
        resubmit them, thus saving bandwidth. You only need to know one of the hashes of the file
        to rescan.

        :param this_hash: An md5/sha1/sha256 hash. You can also specify a CSV list made up of a
        combination of any of the three allowed hashes (up to 25 items), this allows you to perform
        a batch request with just one single call. Note that the file must already be present in our
        file store.
        :param date: Date in %Y%m%d%H%M%S format (example: 20120725170000) in which the rescan should
        be performed. If not specified the rescan will be performed immediately.
        :param period: Periodicity (in days) with which the file should be rescanned. If this argument
        is provided the file will be rescanned periodically every period days, if not, the rescan is
        performed once and not repated again.
        :param repeat:
        :param notify_url:
        :param notify_changes_only:
        :return:
        """
        params = {'apikey': self.api_key, 'hash': this_hash}

        try:
            response = requests.post(self.base + 'file/rescan', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def cancel_rescan_file(self, this_hash):
        """ Delete a previously scheduled scan.

        :param this_hash:
        :return:
        """
        params = {'apikey': self.api_key, 'hash': this_hash}

        try:
            response = requests.post(self.base + 'rescan/delete', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_file_report(self, this_hash, allinfo='1'):
        """ Get the scan results for a file.

        :param this_hash:
        :param allinfo:
        :return:
        """
        params = {'apikey': self.api_key, 'resource': this_hash, 'allinfo': allinfo}

        try:
            response = requests.get(self.base + 'file/report', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_file_behaviour(self, this_hash):
        """ Get a report about the behaviour of the file in sand boxed environment.

        :param this_hash:
        :return:
        """
        params = {'apikey': self.api_key, 'hash': this_hash}

        try:
            response = requests.get(self.base + 'file/behaviour', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_network_traffic(self, this_hash):
        """ Get a dump of the network traffic generated by the file.

        VirusTotal runs a distributed setup of Cuckoo sandbox machines that execute the files we receive.
        Execution is attempted only once, upon first submission to VirusTotal, and only Portable Executables
        under 10MB in size are ran. The execution of files is a best effort process, hence, there are no
        guarantees about a report being generated for a given file in our dataset.

        Files that are successfully executed may communicate with certain network resources, all this
        communication is recorded in a network traffic dump (pcap file). This API allows you to retrieve
        the network traffic dump generated during the file's execution.

        :param this_hash: The md5/sha1/sha256 hash of the file whose network traffic dump you want to retrieve.
        :return:
        """
        params = {'apikey': self.api_key, 'hash': this_hash}

        try:
            response = requests.get(self.base + 'file/network-traffic', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
            # ms = magic.magic_open(magic.MAGIC_NONE)
            # ms.load()
            # return ms.buffer(response.text)
        else:
            return dict(response_code=response.status_code)

    def file_search(self, search_options, offset=300):
        """ Search for samples.
        https://www.virustotal.com/intelligence/help/file-search/#search-modifiers

        EXAMPLE:
        search_options = 'type:peexe size:90kb+ positives:5+ behaviour:"taskkill"'

        :param search_options:
        :param offset:
        :return:
        """
        params = {'apikey': self.api_key, 'query': search_options}

        try:
            response = requests.get(self.base + 'file/search', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_file_clusters(self, this_date):
        """ File similarity clusters for a given time frame.

        :param this_date:
        :return:
        """
        params = {'apikey': self.api_key, 'date': this_date}

        try:
            response = requests.get(self.base + 'file/clusters', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_file_distribution(self, before='', after='', reports='false', limit='1000'):
        """ Get a live feed with the latest files submitted to VirusTotal.

        :param before:
        :param after:
        :param reports:
        :param limit:
        :return:
        """
        params = {'apikey': self.api_key, 'before': before, 'after': after, 'reports': reports, 'limit': limit}

        try:
            response = requests.get(self.base + 'file/distribution', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_file(self, this_hash):
        """ Download a file by its hash.

        :param this_hash:
        :return:
        """
        params = {'apikey': self.api_key, 'hash': this_hash}

        try:
            response = requests.get(self.base + 'file/download', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def scan_url(self, this_url):
        """ Submit a URL to be scanned by VirusTotal.

        :param this_url:
        :return:
        """
        params = {'apikey': self.api_key, 'url': this_url}

        try:
            response = requests.post(self.base + 'url/scan', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_url_report(self, this_url, scan='0', allinfo='1'):
        """ Get the scan results for a URL.

        :param this_url:
        :param scan:
        :param allinfo:
        :return:
        """
        params = {'apikey': self.api_key, 'resource': this_url, 'allinfo': allinfo}

        try:
            response = requests.get(self.base + 'url/report', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_url_distribution(self, before='', after='', allinfo=1, limit='1000'):
        """ Get a live feed with the lastest URLs submitted to VirusTotal.

        :param before:
        :param after:
        :param allinfo:
        :param limit:
        :return:
        """
        params = {'apikey': self.api_key, 'before': before, 'after': after, 'allinfo': allinfo, 'limit': limit}

        try:
            response = requests.get(self.base + 'url/distribution', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def put_comments(self, resource, comment):
        """ Post a comment on a file or URL.

        :param resource:
        :param comment:
        :return:
        """
        params = {'apikey': self.api_key, 'resource': resource, 'comment': comment}

        try:
            response = requests.post(self.base + 'comments/put', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_ip_report(self, this_ip):
        """ Get information about a given IP address.

        :param this_ip:
        :return:
        """
        params = {'apikey': self.api_key, 'ip': this_ip}

        try:
            response = requests.get(self.base + 'ip-address/report', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_domain_report(self, this_domain):
        """ Get information about a given domain.

        :param this_domain:
        :return:
        """
        params = {'apikey': self.api_key, 'domain': this_domain}

        try:
            response = requests.get(self.base + 'domain/report', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_comments(self, resource, before=''):
        """ Get comments for a file or URL.

        :param resource:
        :param before:
        :return:
        """
        params = {'apikey': self.api_key, 'resource': resource}

        try:
            response = requests.get(self.base + 'comments/get', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)


class IntelApi():
    """ To make the best use of your VirusTotal Intelligence account and so, we have exposed some
    VirusTotal Intelligence functionality for programmatic interaction even if you do not have a
    Private Mass API key.
    """

    def __init__(self, api_key, proxies=None):
        self.api_key = api_key
        self.proxies = proxies
        self.base = 'https://www.virustotal.com/intelligence/'

    def get_hashes_from_search(self, query, page=None):
        """ Get the scan results for a file.

        :param query: a VirusTotal Intelligence search string in accordance with the file search documentation .
            <https://www.virustotal.com/intelligence/help/file-search/>
        :param page: the next_page property of the results of a previously issued query to this API. This parameter
            should not be provided if it is the very first query to the API, i.e. if we are retrieving the
            first page of results.
        apikey: the API key associated to a VirusTotal Community account with VirusTotal Intelligence privileges.
        """
        params = {'query': query, 'apikey': self.api_key, 'page': page}

        try:
            response = requests.get(self.base + 'search/programmatic/', params=params, proxies=self.proxies)
        except Exception:
            return dict(error=Exception)
        next_page = response.json()['next_page']
        return next_page, response

    def get_file(self, file_hash, local_filename):
        """ Get the scan results for a file.

        :param file_hash: You may use either the md5, sha1 or sha256 hash of the file in order to download it.
        :param local_filename:
        """
        params = {'hash': file_hash, 'apikey': self.api_key}

        try:
            response = requests.get(self.base + 'download/', params=params, proxies=self.proxies, stream=True)
        except Exception:
            return dict(error=Exception)

        if response.status_code == requests.codes.ok:
            return response.json()
        else:
            return dict(response_code=response.status_code)

    def get_all_file_report_pages(self, query):
        """

        :param query:
        :return:
        """
        responses = []
        next_page, response = self.get_hashes_from_search(self, query)
        responses.append(response)
        while next_page:
            next_page, response = self.get_hashes_from_search(self, query, next_page)
            responses.append(response)
        return responses

    def save_downloaded_file(self, local_filename):
        """

        :param local_filename:
        """
        with open(local_filename, 'wb') as f:
            for chunk in requests.iter_content(chunk_size=1024):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
                    f.flush()