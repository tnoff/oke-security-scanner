"""Container image reference, shared by every package that talks to OCIR
or discovers deployed images via Kubernetes.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Self


@dataclass(unsafe_hash=True)
class Image:
    '''Base image'''
    full_name: str
    # Ocid if ocir image
    ocid: str = None
    created_at: datetime = None
    digest: str = None
    repo_name: str = field(init=False)
    tag: str = field(init=False)
    registry: str = field(init=False)

    def __post_init__(self):
        # Init the rest
        parsed = self.full_name.split(':')
        # Strip digest (@sha256:...) from the tag if present
        self.tag = parsed[1].split('@')[0]
        self.repo_name = parsed[0]
        if self.full_name.count('/') < 2:
            self.registry = "docker.io"
        else:
            repo_parsed = parsed[0].split('/')
            self.repo_name = '/'.join(i for i in repo_parsed[1:])
            self.registry = repo_parsed[0]

    def __eq__(self, value: Self) -> bool:
        return self.full_name == value.full_name

    def __lt__(self, value: Self) -> bool:
        if self.created_at and value.created_at:
            return self.created_at < value.created_at
        return self.full_name < value.full_name

    def __str__(self):
        return self.full_name

    @property
    def is_ocir_image(self) -> bool:
        '''Check if ocir registry'''
        return 'ocir' in self.registry
