"""Discord webhook notifications for OCIR cleanup results."""

from collections import defaultdict
from logging import getLogger
from typing import List

from dappertable import DapperTable, Column, Columns, PaginationLength
from oke_scanner_core.discord_webhook import DiscordWebhookClient
from oke_scanner_core.image import Image

from .registry_client import CleanupRecommendation

logger = getLogger(__name__)


class DiscordNotifier:
    """Send OCIR cleanup results to Discord via webhook."""

    def __init__(self, webhook_url: str):
        self._client = DiscordWebhookClient(webhook_url)

    @property
    def max_length(self) -> int:
        return self._client.max_length

    @max_length.setter
    def max_length(self, value: int) -> None:
        self._client.max_length = value

    def send_cleanup_recommendations(self, cleanup: list[CleanupRecommendation]):
        '''Send cleanup recommendation'''
        full_report_table = DapperTable(columns=Columns([
            Column('Image', 64),
            Column('Tag', 12),
            Column('Created At', 36),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix='## Images That Can Be Deleted\n')

        for report in cleanup:
            for tag in report.tags_to_delete:
                full_report_table.add_row([
                    f'{report.registry}/{report.repository}',
                    tag.tag,
                    tag.created_at.strftime('%Y-%m-%d %H-%M-%S')
                ])
        if len(full_report_table):
            content = full_report_table.render()
        else:
            content = ['## No Images That Require Deletion\n']
        self._client.send_message(content)

    def send_deletion_results(self, images: list[Image],
                              scanned_repos: list[str] = None,
                              is_orphaned: bool = False):
        '''Send deletion results, reported per repository.

        Emits one entry per repository that was scanned so it's obvious which
        repos were checked: the tags that were deleted (in a code block) under
        the repo, or an explicit "No <repo> ... deleted" line for repos that
        came back clean. ``scanned_repos`` is the full set of ``registry/repo``
        names that were considered; without it only repos with deletions are
        listed.
        '''
        noun = 'orphan intermediate image' if is_orphaned else 'image'

        deleted_by_repo = defaultdict(list)
        for image in images:
            tag = image.tag if image.tag != 'unknown' else image.digest
            deleted_by_repo[f'{image.registry}/{image.repo_name}'].append(tag)

        all_repos = set(scanned_repos or ()) | set(deleted_by_repo)
        if not all_repos:
            self._client.send_message([f'No {noun}s were deleted.'])
            return

        # Deleted repos first (the actionable part), then the clean ones.
        clean_repos = sorted(all_repos - set(deleted_by_repo))
        blocks = []
        for repo in sorted(deleted_by_repo):
            label = repo.split('/')[-1]
            tags = sorted(deleted_by_repo[repo])
            blocks.extend(self._format_deleted_repo(label, tags, noun))
        for repo in clean_repos:
            blocks.append(f'No {repo.split("/")[-1]} {noun}s deleted.')

        # Only headline when something was actually deleted — an all-clean run
        # reads as a list of "No <repo> ... deleted" lines, not a lone heading.
        heading = ''
        if deleted_by_repo:
            heading = ('## Orphan Intermediate Images Deleted'
                       if is_orphaned else '## Images Deleted')
        self._client.send_message(self._pack_blocks(heading, blocks))

    def _format_deleted_repo(self, label: str, tags: List[str], noun: str) -> List[str]:
        '''Render a repo's deleted tags into one or more code-block segments.

        Tags are split across multiple code blocks if a single one would exceed
        Discord's message limit.
        '''
        header = f'Deleted {len(tags)} {label} {noun if len(tags) == 1 else f"{noun}s"}:'
        # Reserve room for the header line and the ``` fences/newlines.
        budget = self.max_length - len(header) - len('\n```\n\n```')
        chunks = []
        current = []
        length = 0
        for tag in tags:
            if current and length + len(tag) + 1 > budget:
                chunks.append(current)
                current = []
                length = 0
            current.append(tag)
            length += len(tag) + 1
        if current:
            chunks.append(current)

        segments = []
        for idx, chunk in enumerate(chunks):
            head = header if idx == 0 else f'{header} (continued)'
            body = '\n'.join(chunk)
            segments.append(f'{head}\n```\n{body}\n```')
        return segments

    def _pack_blocks(self, heading: str, blocks: List[str]) -> List[str]:
        '''Greedily pack rendered blocks into messages under the Discord limit.

        The heading (if any) leads the first message; individual blocks are
        never split across messages.
        '''
        messages = []
        current = heading
        for block in blocks:
            if not current:
                current = block
            elif len(current) + 1 + len(block) <= self.max_length:
                current = f'{current}\n{block}'
            else:
                messages.append(current)
                current = block
        if current:
            messages.append(current)
        return messages
