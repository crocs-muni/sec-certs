from sec_certs.dataset.common_criteria import CCDataset

#dset = CCDataset.from_web_latest()
#dset.to_json('/home/george/SBAPR/datasets/cert_id_dset')
dset = CCDataset.from_json('/home/george/SBAPR/datasets/cert_id_dset.json')
#dset._compute_cert_ids()

print(len(dset.get_all_cert_id_references))
print("Done")
