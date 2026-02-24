from unification_dictionaries import manufacturer_mapping, manufacturer_patterns, suffixes_to_remove, comma_exceptions

def pre_process_manufacturer(manufacturer):
    manufacturer_items = [item.strip() for item in manufacturer.split(',')]
    for manufacturer_item in manufacturer_items:
        if manufacturer_item.strip(' ').lower() in suffixes_to_remove:
            manufacturer_items.remove(manufacturer_item)
    return ' / '.join(manufacturer_items)


def unify_manufacturer(manufacturer):
    if manufacturer.lower() in manufacturer_mapping:
       return manufacturer_mapping[manufacturer.lower()]
        
    manufacturer_lower = manufacturer.lower().strip(' ')
    for pattern, replacement in manufacturer_patterns.items():
        if pattern in manufacturer_lower:
            return replacement
            
    return manufacturer


def process_multiple_manufacturers(manufacturer):
    multiple_manufacturers = manufacturer.split(' / ')
    result = []
    for single_manufacturer in multiple_manufacturers:
        result.append(unify_manufacturer(single_manufacturer))
    return ' / '.join(result)


def process_manufacturer_names(dset_to_process, field_name):
    for index, cert in dset_to_process.iterrows():
        manufacturer = str(cert[field_name])
        
        if manufacturer in comma_exceptions:
            dset_to_process.at[index, field_name] = comma_exceptions[manufacturer]
            continue

        pre_processed_manufacturer = pre_process_manufacturer(manufacturer).split(' / ')[0]
        dset_to_process.at[index, field_name] = unify_manufacturer(pre_processed_manufacturer)
    
    return dset_to_process