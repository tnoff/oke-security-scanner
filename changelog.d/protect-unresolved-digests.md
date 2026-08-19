OCIR cleanup now fails safe when a digest does not resolve: a repo with an unprotectable surviving tag is skipped entirely, and a delete candidate with no digest of its own is never pruned.
