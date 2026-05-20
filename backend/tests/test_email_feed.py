import unittest

from app.services.email_service import normalize_email_values


class EmailFeedTest(unittest.TestCase):
    def test_normalize_email_values_parses_display_names_and_lists(self) -> None:
        values = normalize_email_values(
            "SOC Sender <sender@example.com>",
            ["User One <mailbox@example.com>", "other@example.com"],
            "mailbox@example.com",
        )
        self.assertIn("sender@example.com", values)
        self.assertIn("mailbox@example.com", values)
        self.assertIn("other@example.com", values)

    def test_imap_mailbox_matches_when_recipients_missing(self) -> None:
        values = normalize_email_values("", [], "mailbox@example.com")
        self.assertEqual(values & {"mailbox@example.com"}, {"mailbox@example.com"})


if __name__ == "__main__":
    unittest.main()
