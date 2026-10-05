"""Analyseurs : transforment un message brut d'un outil en Event normalisé."""

from minisoc.parsers.dispatch import parse_message

__all__ = ["parse_message"]
