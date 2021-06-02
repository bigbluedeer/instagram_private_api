# flake8: noqa
from .accounts import AccountsEndpointsMixin
from .collections import CollectionsEndpointsMixin
from .common import (
    ClientDeprecationWarning,
    ClientPendingDeprecationWarning,
    ClientExperimentalWarning,
)
from .discover import DiscoverEndpointsMixin
from .feed import FeedEndpointsMixin
from .friendships import FriendshipsEndpointsMixin
from .highlights import HighlightsEndpointsMixin
from .igtv import IGTVEndpointsMixin
from .live import LiveEndpointsMixin
from .locations import LocationsEndpointsMixin
from .media import MediaEndpointsMixin
from .misc import MiscEndpointsMixin
from .tags import TagsEndpointsMixin
from .upload import UploadEndpointsMixin
from .users import UsersEndpointsMixin
from .usertags import UsertagsEndpointsMixin
