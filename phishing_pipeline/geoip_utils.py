import sys, asyncio
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import numpy as np
import geoip2.database

def enrich_with_geoip(df, asn_db_path, city_db_path):
    try:
        asn_reader  = geoip2.database.Reader(asn_db_path)
        city_reader = geoip2.database.Reader(city_db_path)
    except Exception:
        df["asn"] = None; df["asn_org"] = None
        df["country"] = None; df["region"] = None; df["city"] = None
        return df

    asn_list, asn_org_list, country_list, region_list, city_list = [], [], [], [], []
    for ip in df.get('ip_address', []):
        if not ip or (isinstance(ip, float) and np.isnan(ip)):
            asn_list.append(None); asn_org_list.append(None)
            country_list.append(None); region_list.append(None); city_list.append(None)
            continue
        try:
            ar = asn_reader.asn(ip)
            asn_list.append(ar.autonomous_system_number)
            asn_org_list.append(ar.autonomous_system_organization)
        except:
            asn_list.append(None); asn_org_list.append(None)
        try:
            cr = city_reader.city(ip)
            country_list.append(cr.country.iso_code)
            region_list.append(cr.subdivisions.most_specific.name)
            city_list.append(cr.city.name)
        except:
            country_list.append(None); region_list.append(None); city_list.append(None)

    try:
        asn_reader.close(); city_reader.close()
    except Exception:
        pass

    df['asn'] = asn_list
    df['asn_org'] = asn_org_list
    df['country'] = country_list
    df['region'] = region_list
    df['city'] = city_list
    return df
