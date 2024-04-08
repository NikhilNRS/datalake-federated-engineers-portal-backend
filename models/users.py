from starlette.authentication import SimpleUser


class CognitoUser(SimpleUser):
    def __init__(
        self,
        username: str,
        groups: list[str],
        group_login_links_mapping: dict[str, str],
        first_name: str,
        last_name: str
    ):
        super().__init__(username)

        self.groups = groups
        self.login_links = group_login_links_mapping
        self.first_name = first_name
        self.last_name = last_name

