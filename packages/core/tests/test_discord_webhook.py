"""Tests for the low-level Discord webhook client."""

from unittest.mock import Mock, patch

from oke_scanner_core.discord_webhook import DiscordWebhookClient


@patch('oke_scanner_core.discord_webhook.time.sleep')
@patch('oke_scanner_core.discord_webhook.requests.post')
def test_send_message_posts_each_content_item(mock_post, _mock_sleep):
    mock_post.return_value = Mock(status_code=200)
    mock_post.return_value.raise_for_status = Mock()

    client = DiscordWebhookClient("https://discord.com/api/webhooks/test")
    client.send_message(["first", "second"])

    assert mock_post.call_count == 2
    assert mock_post.call_args_list[0].kwargs['json'] == {"content": "first"}
    assert mock_post.call_args_list[1].kwargs['json'] == {"content": "second"}
    for call in mock_post.call_args_list:
        assert call.kwargs['timeout'] == 10


@patch('oke_scanner_core.discord_webhook.time.sleep')
@patch('oke_scanner_core.discord_webhook.requests.post')
def test_send_message_raises_on_http_error(mock_post, _mock_sleep):
    mock_post.return_value = Mock(status_code=500)
    mock_post.return_value.raise_for_status.side_effect = Exception("boom")

    client = DiscordWebhookClient("https://discord.com/api/webhooks/test")
    try:
        client.send_message(["oops"])
        assert False, "expected raise_for_status to propagate"
    except Exception as e:  # pylint: disable=broad-except
        assert str(e) == "boom"


@patch('oke_scanner_core.discord_webhook.requests.post')
def test_send_file_posts_multipart_with_attachment(mock_post):
    mock_post.return_value = Mock(status_code=200)
    mock_post.return_value.raise_for_status = Mock()

    client = DiscordWebhookClient("https://discord.com/api/webhooks/test")
    client.send_file("## Report", "a,b,c\n1,2,3", "report.csv")

    mock_post.assert_called_once()
    call = mock_post.call_args
    assert call.kwargs['data'] == {"content": "## Report"}
    assert call.kwargs['files']['file'][0] == "report.csv"
    assert call.kwargs['files']['file'][1] == "a,b,c\n1,2,3"
    assert call.kwargs['timeout'] == 10
