## New CommonCriteria API

The file [cc_oop_demo.py](cc_oop_demo.py) contains a rough overview of public methods available on `CCDataset`. The chain in which the methods are run roughly corresponds to running `cc-certs all` with CLI.


## Manual CPE labeling

The tool contains a fuzzy procedure that attempts to map [CPE names](https://nvd.nist.gov/products/cpe) to CC certificates. Result is a list of potentially promising matchings that should be manually evaluated by an analyst to obtain ground truth labeling. There are two ways of how one can manually evaluate the suggested matches:

1. Exporting the matches into [label studio](https://labelstud.io/) format, label them there and import the acquired ground truth back into dataset
2. Do the same thing using command line prompts (unrecommended, further unmaintained)

We proceed with description of both methods.

### Labeling in Label studio

[Label studio](https://labelstud.io/) is a web UI for labeling of datasets. To label CPE dataset, one must do the following:

1. Export the candidate matches into json that can be imported into label studio

```python
dset = CCDataset.from_json('path/to/your/dataset.json')
dset.to_label_studio('./label_studio_input.json')
```

2. Label the instances in the label studio, choose the labeling interface according to example in [label_studio_interface.txt](label_studio_interface.txt) and export them using [JSON-MIN](https://labelstud.io/guide/export.html#JSON-MIN) option into a file, say `./label_studio_output.json`.
3. Import them back into your dataset and save the updated version of the dataset

```python
dset = CCDataset.from_json('path/to/your/dataset.json')
dset.load_label_studio_labels('./label_studio_output.json', update_json=True)
```

:tada you should now have your dataset labeled.

### Manual labeling

The analyst should run the file [cc_cpe_labeling.py](cc_cpe_labeling.py)

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

```python
dset = CCDataset.from_json('./my_debug_datset/cc_full_dataset.json')
dset.manually_verify_cpe_matches()
```
