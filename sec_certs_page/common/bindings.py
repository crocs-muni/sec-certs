import os
import json
import datetime
import asyncio
import hashlib
import shutil
import urllib
from typing import Tuple, Union, Any
import requests
import jwt
import click
from flask import current_app
from pymongo.collection import Collection


from .. import mongo

Document = Any


class Binding():
    """ A binding data class
    """

    def __init__(self, cert_id: str, header_name: str):
        """Binding object constructor

        Args:
            cert_id (str): certificate id
            header_name (str): header name
        """
        self.cert_id: Union[str, int] = cert_id if not cert_id.isdigit() else int(
            cert_id)
        self.header_name: str = header_name
        self.header_data: list[object] = []

    def match_name(self, name: str) -> bool:
        """ Function to match a string to the header_name

        Args:
            name (str): Match candidate

        Returns:
            bool: Whether the name matches to the binding obj header_name
        """
        return name == urllib.parse.quote(
            self.header_name) or name == self.header_name

    def update_headers_if_match(self, name: str, header: list[object]) -> None:
        """ Update header_data if this objects header_name matches with given name

        Args:
            name (str): Match candidate
            header (list[object]): New header data
        """
        if self.match_name(name):
            self.header_data = header

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"Binding {self.cert_id} to {self.header_name}"

    def __getitem__(self, key: str) -> Union[str, int, list[object]]:
        return {
            "cert_id": self.cert_id,
            "header_name": self.header_name,
            "header_data": self.header_data
        }[key]


def url_to_local_path(url: str) -> str:
    """ Transorms local URL to local path

    Args:
        url (str): URL to transform

    Returns:
        str: Transformed URL
    """
    parsed_url = urllib.parse.urlparse(url)
    path = urllib.parse.unquote(parsed_url.path.strip("/"))
    return path


def github_url_to_api(url: str) -> str:
    """ Transform the standard public github URL to a github API URL

    Args:
        url (str): URL to transform

    Returns:
        str: Transformed API URL
    """
    parsed_url = urllib.parse.urlparse(url)
    api_url = f"https://api.github.com/repos{parsed_url.path}"
    if parsed_url.query:
        api_url += f"?{parsed_url.query}"
    return api_url


def get_filename_from_url(url: str) -> str:
    """ Parse out the filename from a given url

    Args:
        url (str): URL to parse

    Returns:
        str: Parsed out filename
    """
    path_components = url.split("/")
    filename = path_components[-1]
    if not filename:
        filename = path_components[-2]
    return os.path.basename(filename)


def verify_timestamp(timestamp: str) -> bool:
    """ Verifies timestamp validity

    Args:
        timestamp (str): timestamp to validate

    Returns:
        bool: Whether the given timestamp is valid
    """
    try:
        datetime.datetime.fromisoformat(timestamp)
        return True
    except ValueError:
        return False


def verify_url(url: str) -> bool:
    """ Verifies URL validity

    Args:
        url (str): URL to validate

    Returns:
        bool: Whether the given URL is valid
    """
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def verify_jwt(data: dict[str, Union[str, object]]) -> bool:
    """ Verifies the given object jwt validity

    Args:
        data (dict[str, Union[str, object]]): object to validate

    Returns:
        bool: Whether the JWT in the data object is valid
    """
    jwt_token = data['JWT']
    del data["JWT"]
    encoded_jwt = jwt.encode(
        data, key=current_app.config["BINDINGS_SECRET_KEY"], algorithm="HS256")
    if not jwt_token:
        click.echo("JWT token is missing")
        return False
    if encoded_jwt != jwt_token:
        return False
    return True


async def download_file(file_url: str, file_path: str, sha256: str = "", verbose: bool = False) -> None:
    """ Download a file from the given URL

    Args:
        file_url (str): URL of the file to download
        file_path (str): Path to where to download the file
        sha256 (str, optional): Expected hash of the downloaded file. Defaults to "".
        verbose (bool, optional): Whether to click.echo out extra information. Defaults to False.
    """
    if verbose:
        click.echo(f"Downloading {file_url}...")
    response = requests.get(file_url, timeout=1000)
    if sha256:
        file_sha256 = hashlib.sha256(response.content).digest().hex()
        if file_sha256 != sha256:
            click.echo(
                f"Metadata SHA256 verification failed for file {file_path.split('/')[-1]}")
    try:
        with open(file_path, "wb") as f:
            f.write(response.content)
    except:
        click.echo(f"Cant open url from file {file_url}")
    if verbose:
        click.echo(f"Downloaded {file_url}.")


async def download_binding_files(url: str, output_dir: str, file_ext: str = ".json", verbose: bool = False) -> None:
    """ Download all binding files from a given url.

    Args:
        url (str): URL to download binding files from
        output_dir (str): Path to write binding files to
        file_ext (str): Optional file extension of binding files to be downloaded
        verbose (bool, optional): Whether to click.echo out extra information. Defaults to False.
    """
    if verbose:
        click.echo(f"Downloading bindings files from {url}")

    if url.startswith("https://github.com"):
        tasks = []
        repo_url = url.split("/tree")[0]
        dir_path = url.split("/main")[1]
        api_url = github_url_to_api(repo_url) + "/contents" + dir_path

        response = requests.get(api_url)
        data = {}
        if response.status_code == 200:
            try:
                data = response.json()
            except json.decoder.JSONDecodeError as e:
                click.echo(f"Error decoding JSON: {e}")
                click.echo(
                    f"Response content: {response.text.splitlines()[:5]}")
                return
        else:
            click.echo(
                f"Request failed with status code {response.status_code} - {response.reason}"
            )
        files = [
            (file["name"], file["download_url"])
            for file in data
            if file["name"].endswith(file_ext)
        ]

        for file_name, file_url in files:
            tasks.append(asyncio.create_task(
                download_file(
                    file_url,
                    os.path.join(output_dir, file_name),
                    verbose=verbose)))

        await asyncio.gather(*tasks)
        if verbose:
            click.echo(
                f"Downloaded {len(tasks)} {file_ext} files from {url} to {output_dir}.")

    elif os.path.isdir(url_to_local_path(url)):
        path = url_to_local_path(url)
        for file_name in os.listdir(path):
            if verbose:
                click.echo(f"copying local file: {file_name}")
            if file_name.endswith(f".{file_ext}"):
                shutil.copy(os.path.join(path, file_name),
                            os.path.join(output_dir, file_name))
        if verbose:
            click.echo(
                f"Copied {len(os.listdir(path))} {file_ext} files from {path} to {output_dir}.")
    else:
        click.echo(f"Error: Unsupported URL format of: {url}")


def download_all_bindings_sync(
        urls: list[str],
        output_dir: str,
        verbose: bool = False) -> None:
    """ Download binding files from all given URLs

    Args:
        urls (list[str]): list of URLs to download from
        output_dir (str): Path to write the binding files
        verbose (bool, optional): Whether to click.echo out extra information. Defaults to False.
    """
    os.makedirs(output_dir, exist_ok=True)

    for url in urls:
        asyncio.run(
            download_binding_files(
                url,
                output_dir,
                verbose=verbose))
        if verbose:
            click.echo(f"Download completed for {url}.\n")


async def process_binding_files(bindings_dir: str, download_dir: str, download_headers: bool = True, verbose: bool = True) -> list[Binding]:
    """ Processing of all binding files in given directory

    Args:
        bindings_dir (str): Directory where binding files are located
        download_dir (str): Directory where binding files are to be downloaded
        download_headers (bool, optional): Whether to download the headers files. Defaults to True.
        verbose (bool, optional): _description_. Defaults to True.

    Returns:
        list[Binding]: list of binding Objects identified in the binding files
    """
    os.makedirs(download_dir, exist_ok=True)
    tasks = []
    bindings = []
    for filename in os.listdir(bindings_dir):
        if filename.endswith(".json"):
            if verbose:
                click.echo(f"\nProcessing binding file: {filename}")
            filepath = os.path.join(bindings_dir, filename)
            with open(filepath, "r", encoding="utf8") as f:
                data = json.load(f)
                if not verify_jwt(data):
                    click.echo(
                        f"JWT verification failed processing binding file {filename}")
                    continue
                for item in data["data"]:
                    timestamp = item["timestamp"]
                    if not verify_timestamp(timestamp):
                        click.echo(f"Invalid timestamp for file: {filename}")
                        continue
                    url = item["metadata_header_url"]
                    header_file_name = get_filename_from_url(
                        urllib.parse.unquote(url))
                    if not verify_url(url):
                        click.echo(
                            f"Invalid metadata_header_url for file: {url}")
                        continue
                    if not download_headers:
                        continue

                    for cert_id in item["certificate_ids"]:
                        bindings.append(Binding(cert_id, header_file_name))
                    if os.path.exists(
                            url_to_local_path(url)) and download_headers:
                        click.echo(
                            f"Copying header file from: {url_to_local_path(url)}")
                        shutil.copy(url_to_local_path(url), os.path.join(
                            download_dir, header_file_name
                        ))
                        continue
                    tasks.append(asyncio.create_task(
                        download_file(url, os.path.join(
                            download_dir, header_file_name
                        ), verbose=verbose)))

    click.echo(f"Identified {len(bindings)} bindings")
    click.echo(f'\nDownloading {len(tasks)} header files')
    await asyncio.gather(*tasks)
    return bindings


async def process_header_files(headers_dir: str, download_dir: str, bindings: list[Binding], download_metadata: bool = True, verbose: bool = False) -> None:
    """Function to process all JSON header files in a given directory

    Args:
        headers_dir (str): Path to the directory containing the JSON header files
        download_dir (str): Where to download the header files to
        bindings (list[Binding]): Bindings objects to be enriched with header_data
        download_metadata (bool, optional): Whether to download the metadata files. Defaults to True.
        verbose (bool, optional): Whether to click.echo out extra information. Defaults to False.
    """
    if verbose:
        click.echo(f"Processing header files in {headers_dir}")
    os.makedirs(download_dir, exist_ok=True)
    tasks = []
    for file_name in os.listdir(headers_dir):
        if file_name.endswith(".json"):
            file_path: str = os.path.join(headers_dir, file_name)
            with open(file_path, "r", encoding="utf8") as f:
                if verbose:
                    click.echo(f"Processing {file_name}")
                json_obj = json.load(f)
                if not verify_jwt(json_obj):
                    click.echo(
                        f"JWT verification failed for header file {file_name}")
                    continue
                for data_obj in json_obj["data"]:
                    if not verify_timestamp(data_obj["timestamp"]):
                        click.echo(f"Invalid timestamp in file {file_name}")
                        continue
                    if not verify_url(data_obj["metadata_url"]):
                        click.echo(f"Invalid URL in file {file_name}")
                        continue
                    download_destination = os.path.join(
                        download_dir, data_obj["metadata_url"].split("/")[-1])
                    if download_metadata:
                        tasks.append(
                            asyncio.create_task(
                                download_file(
                                    data_obj["metadata_url"],
                                    download_destination,
                                    data_obj["metadata_sha256"], verbose)))
                for binding in bindings:
                    binding.update_headers_if_match(
                        file_name, json_obj["data"])

    click.echo(f"Downloading {len(tasks)} metadata files")
    await asyncio.gather(*tasks)


def get_instance_paths() -> Tuple[str, str, str]:
    """ Get instance paths for bindings, headers and metadata files

    Returns:
        Tuple[str, str, str]: The three bindings, headers and metadata files directories paths
    """
    instance_path = current_app.instance_path
    return (
        os.path.join(instance_path, "bindings"),
        os.path.join(instance_path, "headers"),
        os.path.join(instance_path, "metadata")
    )


def process_and_download_all(
        download_bindings: bool = True,
        download_headers: bool = True,
        download_metadata: bool = True,
        verbose: bool = False) -> list[Binding]:
    """ Encapsulates the function calls to download all bindings, process them and to process all header files

    Args:
        download_bindings (bool, optional): Whether to download binding files. Defaults to True.
        download_headers (bool, optional): Whether to download header files. Defaults to True.
        download_metadata (bool, optional): Whether to download metadata files. Defaults to True.
        verbose (bool, optional): Whether to click.echo out extra information. Defaults to False.

    Returns:
        list[Binding]: _description_
    """
    bindings_path, headers_path, metadata_path = get_instance_paths()
    binding_urls = current_app.config["BINDING_URLS"]
    if download_bindings:
        download_all_bindings_sync(
            binding_urls, bindings_path, verbose=verbose)
    bindings = asyncio.run(process_binding_files(
        bindings_path, headers_path, download_headers, verbose=verbose))
    asyncio.run(
        process_header_files(
            headers_path,
            metadata_path,
            bindings,
            download_metadata,
            verbose=verbose))
    return bindings


def purge_headers_data(collection: Collection[Document]) -> None:
    """ Purges all existing headers_data from the MongoDB collection

    Args:
        collection (Collection[Document]): MongoDB collection to purge headers from
    """
    result = collection.delete_many({})
    print(f"Deleted {result.deleted_count} metadata bindings")


def update_one(
        collection: Collection[Document],
        binding: Binding,
        verbose: bool = False) -> None:
    """ Updates a record in mongoDB with new header_data

    Args:
        collection (Collection[Document]): MongoDB collection to update the records in
        binding (Binding): An object representing the binding - cert_id and header_data
        verbose (bool, optional): Whether to click.echo out extra information. Defaults to False.
    """
    cert_id = binding["cert_id"] if "NIST" not in binding["cert_id"] else int(
        binding["cert_id"].strip("NIST-"))
    cert = collection.find_one({"cert_id": cert_id})
    if cert is not None:
        if verbose:
            click.echo(
                f'Found Cert {cert_id}, updating it with {len(binding["header_data"])} new headers.')
            click.echo("Pushing to metadata headers")
        collection.update_one({"cert_id": cert_id}, {"$push": {
            "metadata_headers": binding["header_data"]}})
    else:
        if verbose:
            click.echo("Inserting new metadata binding")
        collection.insert_one(
            {"cert_id": cert_id, "metadata_headers": binding["header_data"]})


def update_bindings(
        download_bindings: bool = True,
        download_headers: bool = True,
        download_metadata: bool = False,
        purge: bool = True, verbose: bool = False) -> None:
    """ Function to be used as a task in seccerts encapsulating all necessary function calls

    Args:
        download_bindings (bool, optional): Whether to download binding files. Defaults to True.
        download_headers (bool, optional): Whether to download header files. Defaults to True.
        download_metadata (bool, optional): Whether to download metadata files. Defaults to True.
        purge (bool, optional): Whether to purge the data before update. Defaults to True.
        verbose (bool, optional): Whether to click.echo out extra information. Defaults to False.
    """
    bindings = process_and_download_all(
        download_bindings,
        download_headers,
        download_metadata,
        verbose=verbose)
    click.echo(
        "\033[32m" +
        "Finished processing bindings, updating mongoDB collections now" +
        "\033[0m")
    collection = mongo.db["metadata_bindings"]
    if purge:
        purge_headers_data(collection)

    for binding in bindings:
        update_one(collection, binding, verbose=verbose)
