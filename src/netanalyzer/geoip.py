import geoip2.database


class GeoIPResolver:

    def __init__(self, db_path):

        self.reader = geoip2.database.Reader(db_path)

    def get_country(self, ip):

        try:
            response = self.reader.country(ip)

            return response.country.name

        except Exception:
            return "Unknown"