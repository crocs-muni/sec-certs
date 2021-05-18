## New CommonCriteria API

New object oriented API. The old one should not be used, unless you explicitly want that. Demo of the tool's capabilities with CommonCriteria dataset can be found in [cc_oop_demo.py](https://github.com/crocs-muni/sec-certs/blob/master/examples/cc_oop_demo.py). Also, comments are provided on separate actions that may serve as a temprorary API documentation :).

To download and build whole dataset can take up to several hours.


## Manual CPE labeling

The tool contains a fuzzy procedure that attempts to map [CPE names](https://nvd.nist.gov/products/cpe) to CC certificates. Result is a list of potentially promising matchings that should be manually evaluated by an analyst to obtain ground truth labeling. The analyst should run the file [cc_cpe_labeling.py](https://github.com/crocs-muni/sec-certs/blob/master/examples/cc_cpe_labeling.py)

```python
dset = CCDataset({}, Path('./my_debug_datset'), 'cc_full_dataset', 'Full CC dataset')
dset.get_certs_from_web(to_download=True, update_json=True)
dset._compute_heuristics()
dset.manually_verify_cpe_matches()
```

For each of the certificates, the user is then prompted for an expert knowledge, see example below:

```
[0/1516] Vendor: NetIQ Corporation, Name: NetIQ Identity Manager 4.7
	- [0]: netiq NetIQ Sentinel CPE-URI: cpe:2.3:a:netiq:sentinel:-:*:*:*:*:*:*:*
	- [1]: netiq NetIQ Sentinel Agent Manager CPE-URI: cpe:2.3:a:netiq:sentinel_agent_manager:-:*:*:*:*:*:*:*
	- [A]: All are fitting
	- [X]: No fitting match
Select fitting CPE matches (split with comma if choosing more):
```

Here, one should type `X` (case insensitive) and press enter, since all guesses are false positives. In different case

```
[1/1516] Vendor: NetIQ, Incorporated, Name: NetIQ Access Manager 4.5
	- [0]: netiq NetIQ Access Manager 4.5 CPE-URI: cpe:2.3:a:netiq:access_manager:4.5:-:*:*:*:*:*:*
	- [1]: netiq NetIQ Access Manager 4.5 Service Pack 1 CPE-URI: cpe:2.3:a:netiq:access_manager:4.5:sp1:*:*:*:*:*:*
	- [2]: netiq NetIQ Access Manager 4.5 Hotfix 1 CPE-URI: cpe:2.3:a:netiq:access_manager:4.5:hotfix1:*:*:*:*:*:*
	- [A]: All are fitting
	- [X]: No fitting match
```

one may answer with `0,1,2` or simply `A` as all CPEs may be releated to the certificate. 

The progress of the expert is periodically saved. Currently, there's no way to gracefully exit the process, just do keyboard interrupt if you want to stop. The json will be updated and next time you will get prompted only for the unlabeled certificates. 

We strongly suggest you try the process with `dset.manually_verify_cpe_matches(update_json=False)` to experiment with correct inputs/outputs. While you will get prompted again if the input is recognized incorrect, the `update_json=False` will not store the results so you can experiment with the tool without loosing your results or creating bad labels.

Would you want to exit in the middle and return back after a while, just exit with CTRL+C. You can then label the rest of the unlabeled certificates with

```
dset = CCDataset.from_json('./my_debug_datset/cc_full_dataset.json')
dset.manually_verify_cpe_matches()
```
