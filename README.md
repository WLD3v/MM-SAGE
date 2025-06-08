# MM-SAGE
MM-SAGE is a multi-modal attack graph generation tool, inspired by the uni-modal attack graph generation tool SAGE.

Please note that the tool is under active construction and might require more setup than described in this document.

## Example Usage
This example demonstrates how to run MM-SAGE using the AIT-ADS and AIT-LDS datasets. Please refer to the Links section below for the needed datasets and tools.

1. Create the `lib` directory in the project root and place the FlexFringe framework inside. See the SAGE repository for instructions on properly configuring FlexFringe for use.
2. Create the `input` directory in the project root and place the AIT-LDS and AIT-ADS inside. The tool looks for these under `input/AIT-LDS` and `input/AIT-ADS`.
3. Run  `collection/alert_collection.py` and `collection/log_collection.py` in order to preprocess and label the datasets.
4. Run `main.py` to generate attack graphs which will be saved under `output/graphs`. Set the `experiment` parameter to 1 if you plan to also evaluate the graphs on correctness, completeness and conciseness.
5. Run `evaluation/graph_quality.py` to evaluate graphs created from each modality combination. The bar charts denoting graph correctness, completeness and conciseness will be saved under `output/evaluation/{ruleset}/{modalities}/charts`.

## Links
AIT-ADS dataset: https://zenodo.org/records/8263181 <br>
AIT-LDS dataset: https://zenodo.org/records/5789064 <br>
Original SAGE: https://github.com/tudelft-cda-lab/SAGE <br>
FlexFringe framework: https://github.com/tudelft-cda-lab/FlexFringe
