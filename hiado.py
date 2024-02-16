import requests
import json
import time
import yaml
import os
import argparse
import sys
import pyfiglet


class pipelineObject:
    def __init__(self, url, repository, name):
        self.name = name
        self.repository = repository
        self.url = url


class color:
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    DARKCYAN = "\033[36m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


# list of permissions array

full_permissions_list = [
    "Contribute",
    "Create branch",
    "Edit policies",
    "Manage permissions",
    "Bypass policies when pushing",
    "Bypass policies when completing pull requests",
    "Contribute to pull requests",
    "Create tag",
    "Delete or disable repository",
    "Force push (rewrite history, delete branches and tags)",
    "Manage notes",
    "Read",
    "Remove others' locks",
    "Rename repository",
]

interesting_permissions_list_wide = [
    "Contribute",
    "Create branch",
    "Edit policies",
    "Manage permissions",
    "Bypass policies when pushing",
]

interesting_permissions_list = ["Contribute", "Create branch", "Manage permissions"]

burp_proxy = {"https": "http://127.0.0.1:8080"}


def get_project_id_subject_descriptor(organization, project_name, user_token):

    url = f"https://dev.azure.com/{organization}/{project_name}?__rt=fps&__ver=2"
    headers = {
        "Host": "dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    }

    response = requests.get(url, headers=headers, timeout=10)
    json_response = response.json()
    content_array_data = (
        json_response.get("fps", {}).get("dataProviders", {}).get("data", {})
    )

    return content_array_data.get("ms.vss-web.page-data", {}).get("user", {}).get(
        "descriptor"
    ), content_array_data.get("ms.vss-tfs-web.page-data", {}).get("project", {}).get(
        "id"
    )


def get_repository_list(organization, project_id, user_token):
    url = f"https://dev.azure.com/{organization}/{project_id}/_apis/git/Repositories"
    headers = {
        "Host": "dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Accept": "application/json;api-version=5.0-preview.1;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    }

    response = requests.get(url, headers=headers, timeout=10)

    return response.json()


def get_repository_permissionset(organization, project_name, user_token):
    url = f"https://dev.azure.com/{organization}/{project_name}/_workitems?__rt=fps&__ver=2"
    headers = {
        "Host": "dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        return (
            response.json()
            .get("fps", {})
            .get("dataProviders", {})
            .get("data", {})
            .get("ms.vss-code-web.versioncontrol-viewmodel-data-provider", {})
            .get("repositoryPermissionSet")
        )
    except Exception:
        return None


def get_project_list(organization, user_token):
    url = (
        f"https://dev.azure.com/{organization}/_apis/projects?api-version=7.1-preview.4"
    )
    headers = {
        "Host": "dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    }

    response = requests.get(url, headers=headers, timeout=10)
    try:
        return response.json().get("value", [])
    except Exception as e:
        print(f"[-] Error while retrieving the list of projects for {str(e)}")
        return []


def retrieve_repository_permissions(
    subject_descriptor,
    project_id,
    repository_id,
    permissionset,
    user_token,
    organization,
):
    url = f"https://dev.azure.com/{organization}/_apis/Contribution/HierarchyQuery"
    headers = {
        "Host": "dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Accept": "application/json;api-version=5.0-preview.1;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Origin": "https://dev.azure.com",
    }

    # Define the JSON payload with variables
    payload_json = {
        "contributionIds": ["ms.vss-admin-web.security-view-permissions-data-provider"],
        "dataProviderContext": {
            "properties": {
                "subjectDescriptor": f"{subject_descriptor}",
                "permissionSetId": f"{permissionset}",
                "permissionSetToken": f"repoV2/{project_id}/{repository_id}",
                "accountName": "",
            }
        },
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload_json))

    try:
        return (
            response.json()
            .get("dataProviders", {})
            .get("ms.vss-admin-web.security-view-permissions-data-provider", {})
            .get("subjectPermissions", [])
        )
    except Exception:
        return None


def find_text_in_file(
    user_token, text, project_id, project_name, repository_name, organization
):
    url = f"https://almsearch.dev.azure.com/{organization}/{project_id}/_apis/search/codesearchresults?api-version=7.1-preview.1"
    headers = {
        "Host": "almsearch.dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Accept": "application/json;api-version=5.0-preview.1;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
    }
    payload_json = {
        "searchText": f"{text}",
        "$skip": 0,
        "$top": 1,
        "filters": {
            "Project": [f"{project_name}"],
            "Repository": [f"{repository_name}"],
            "Path": ["/"],
            "Branch": ["master"],
            "CodeElement": ["def", "class"],
        },
        "$orderBy": [{"field": "filename", "sortOrder": "ASC"}],
        "includeFacets": "true",
    }
    response = requests.post(url, headers=headers, data=json.dumps(payload_json))
    return response.json()


def get_pipeline_details(url, headers):
    response = requests.get(url, headers=headers, timeout=10)
    return response.json()


def get_list_pipelines(user_token, project_name, organization):
    url = f"https://dev.azure.com/{organization}/{project_name}/_apis/pipelines?api-version=7.1-preview.1"
    headers = {
        "Host": "dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        pipelines = []
        for pipeline in response.json().get("value", []):
            pipeline_details = get_pipeline_details(pipeline.get("url"), headers)
            pipelines.append(
                pipelineObject(
                    pipeline.get("url"),
                    pipeline_details.get("configuration", {})
                    .get("repository", {})
                    .get("id"),
                    pipeline_details.get("name"),
                )
            )

        return pipelines
    except Exception:
        return None


def check_trigger_value(user_token, project_name, search_result, organization):
    headers = {
        "Host": "dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    for obj in search_result.get("results", []):
        path = obj.get("path")
        file_extension = os.path.splitext(path)[1]

        if file_extension == ".yaml" or file_extension == ".yml":
            repository_id = obj.get("repository", {}).get("id")
            time.sleep(1)
            url = f"https://dev.azure.com/{organization}/{project_name}/_apis/git/Repositories/{repository_id}/items?path={path}&api-version=7.1-preview.1"
            response = requests.get(url, headers=headers, timeout=10)
            try:
                yaml_content = yaml.safe_load(response.text)
            except Exception as e:
                print(f"[-] Error while loading the yaml file")
                return "none"
            try:
                if isinstance(yaml_content["trigger"], list):
                    return yaml_content["trigger"][0]
                if isinstance(yaml_content["trigger"], dict):
                    return str(yaml_content["trigger"])
                if isinstance(yaml_content["trigger"], str):
                    return yaml_content["trigger"]
            except Exception as e:
                print(f"[-] Error while accessing the trigger key: {str(e)}")
        # print(response.text)
    return "none"


def check_azure_subscription_value(
    user_token, project_name, search_result, organization
):
    result_map = {}
    azure_subscription_findings = []
    headers = {
        "Host": "dev.azure.com",
        "Cookie": f"UserAuthentication={user_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    for obj in search_result.get("results", []):
        path = obj.get("path")
        file_extension = os.path.splitext(path)[1]

        if file_extension == ".yaml" or file_extension == ".yml":
            repository_id = obj.get("repository", {}).get("id")
            time.sleep(1)
            try:
                url = f"https://dev.azure.com/{organization}/{project_name}/_apis/git/Repositories/{repository_id}/items?path={path}&api-version=7.1-preview.1"
                response = requests.get(url, headers=headers, timeout=10)
            except Exception:
                print("[-] Error while checking the azureSubscription values")
                continue
            lines = response.text.split("\n")
            for line in lines:
                if "azureSubscription" in line:
                    azure_subscription_findings.append(
                        (line.replace("azureSubscription:", "")).replace(" ", "")
                    )
            result_map[path] = azure_subscription_findings
    if len(result_map) > 0:
        return result_map
    return None


def check_repo_in_pipelines(pipeline_list, repo_id):
    for pipeline in pipeline_list:
        if pipeline.repository == repo_id:
            return pipeline.name
    return "none"


def check_finding(permission_array_json, interesting_permissions_tocheck):
    permissions_array = []
    for obj in permission_array_json:
        permissions_array.append(obj.get("displayName"))
    if any(x in permissions_array for x in interesting_permissions_tocheck):
        return True
    return False


def validate_options(args):
    if args.check_service_connection is True and args.check_trigger is False:
        raise argparse.ArgumentTypeError(
            "[!] check_service_connection can only be chosen when check_trigger is picked."
        )
    return args


def pick_permissions_list(args):
    if args.interesting_permission.lower() == "interesting":
        return interesting_permissions_list
    elif args.interesting_permission.lower() == "wide":
        return interesting_permissions_list_wide
    elif args.interesting_permission.lower() == "full":
        return full_permissions_list
    else:
        return full_permissions_list


parser = argparse.ArgumentParser(description="Azure DevOps Repository Attacking Tool")

parser.add_argument(
    "-org", "--organization", type=str, required=True, help="Organization name"
)
parser.add_argument(
    "-prj",
    "--project",
    type=str,
    default="none",
    help="Specify here the name of the project you want to check, all the others will be skipped",
)
parser.add_argument(
    "-ct",
    "--check-trigger",
    action="store_true",
    default=False,
    help="Print only results that have a trigger condition set (default: false)",
)
parser.add_argument(
    "-csc",
    "--check-service-connection",
    action="store_true",
    default=False,
    help="Print only results that have an azureSubscription set (default: false)",
)
parser.add_argument(
    "-ip",
    "--interesting-permission",
    type=str,
    required=True,
    help="Choose between: interesting,wide,full",
)
parser.add_argument("-ut", "--user-token", type=str, required=True, help="User token")

args = parser.parse_args()
try:
    args = validate_options(args)
except argparse.ArgumentTypeError as e:
    parser.error(str(e))

interesting_permission_tocheck = pick_permissions_list(args)
organization = args.organization
user_token = args.user_token
projects_list = []
if args.project != "none":
    projects_list.append(args.project)
else:
    projects_list = get_project_list(organization, user_token)

if len(projects_list) == 0:
    print("[-] Error while retrieving the list of projects, exiting")
    sys.exit()

print(pyfiglet.figlet_format("Hiado", font="slant"))

# from now on need to loop through the projects name
for project in projects_list:
    try:
        project_name = project.get("name")
    except AttributeError:
        project_name = projects_list[0]
    print(f"[+] Working on {project_name}")
    subject_descriptor, project_id = get_project_id_subject_descriptor(
        organization, project_name, user_token
    )
    permissionset = get_repository_permissionset(organization, project_name, user_token)
    if permissionset is None or subject_descriptor is None or project_id is None:
        print("[-] Error retrieving project information")
        continue

    print("[+] Found subjectDescriptor: " + subject_descriptor)
    print("[+] Found projectID: " + project_id)
    print("[+] Found repository permissionSet: " + permissionset)

    pipeline_list = get_list_pipelines(user_token, project_name, organization)

    repositories = get_repository_list(organization, project_id, user_token)
    if repositories is None:
        continue

    for obj in repositories:
        time.sleep(2)
        # check if the repo is attached to any pipeline, if not does not matter
        if pipeline_list is not None:
            attached_pipeline = check_repo_in_pipelines(pipeline_list, obj.get("id"))
        # retrieve the permission on the repository
        permissions_array = retrieve_repository_permissions(
            subject_descriptor,
            project_id,
            obj.get("id"),
            permissionset,
            user_token,
            organization,
        )
        # if i was able to retrieve the permissions i move forward
        if permissions_array != None:
            # search all the files that contains the word trigger (filtered also by extension: yaml, yml)
            # the existence of trigger takes priority over the other filters
            if args.check_trigger is True:
                search_result = find_text_in_file(
                    user_token,
                    "trigger",
                    project_id,
                    project_name,
                    obj.get("name"),
                    organization,
                )
                if search_result != None and search_result.get("count") != None:
                    if search_result.get("count") > 0:
                        trigger_value = check_trigger_value(
                            user_token, project_name, search_result, organization
                        )
                        search_result = find_text_in_file(
                            user_token,
                            "azureSubscription",
                            project_id,
                            project_name,
                            obj.get("name"),
                            organization,
                        )
                        azure_subscription = check_azure_subscription_value(
                            user_token, project_name, search_result, organization
                        )
                        # if a trigger value != none has been found i want to proceed
                        if trigger_value is not None and trigger_value != "none":
                            # if i want to check the service connection and the result is none i skip
                            # if csc is false i do not care anyway but it has to be blocking if csc is true and i haven't found any
                            if (
                                args.check_service_connection is True
                                and azure_subscription is None
                            ):
                                continue
                            # if there are any interesting permissons consider the repo a finding and print the details
                            if check_finding(
                                permissions_array, interesting_permission_tocheck
                            ):
                                print(
                                    "\t - name: "
                                    + color.BOLD
                                    + obj.get("name")
                                    + color.END
                                )
                                print("\t - repository id: " + obj.get("id"))
                                print(
                                    "\t - pipeline: " + "empty"
                                    if attached_pipeline == "none"
                                    else "\t - pipeline: " + attached_pipeline
                                )
                                print("\t - trigger condition: " + trigger_value)
                                print("\t - azureSubscription: ")
                                for file, matches in azure_subscription.items():
                                    print(f"\t\t File: {file} - ", end="")
                                    print("Matches: ", end="")
                                    for index, match in enumerate(matches):
                                        if index == len(matches) - 1:
                                            print(match)
                                        else:
                                            print(match + ",", end="")
                                print("\t - Permissions list: ")
                                for perm in permissions_array:
                                    if (
                                        perm.get("displayName")
                                        in interesting_permission_tocheck
                                    ):
                                        if "Allow" in perm.get(
                                            "permissionDisplayString"
                                        ):
                                            print(
                                                "\t\t"
                                                + perm.get("displayName")
                                                + ": "
                                                + color.GREEN
                                                + perm.get("permissionDisplayString")
                                                + color.END
                                            )
            else:
                # just assess the permissions on a given repository
                if check_finding(permissions_array, interesting_permission_tocheck):
                    print("\t - name: " + color.BOLD + obj.get("name") + color.END)
                    print("\t - repository id: " + obj.get("id"))
                    for perm in permissions_array:
                        if perm.get("displayName") in interesting_permission_tocheck:
                            if "Allow" in perm.get("permissionDisplayString"):
                                print(
                                    "\t\t"
                                    + perm.get("displayName")
                                    + ": "
                                    + color.GREEN
                                    + perm.get("permissionDisplayString")
                                    + color.END
                                )
