from starlette.authentication import SimpleUser


class CognitoUser(SimpleUser):
    def __init__(
        self,
        username: str,
        groups: list[str],
        group_login_links_mapping: dict[str, str]
    ):
        super().__init__(username)

        self.groups = groups
        self.login_links = group_login_links_mapping

