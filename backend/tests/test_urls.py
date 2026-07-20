from app.utils.url_utils import normalize_url
from app.utils.url_utils import extract_domain
from app.utils.url_utils import is_valid_url

url = " HTTPS://WWW.Google.com/login/ "

print(normalize_url(url))
print(extract_domain(url))
print(is_valid_url(url))