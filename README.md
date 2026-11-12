# Assignment2 Innovation Project

## Data Processing 

The phishing detector uses three datasets, download and place them in the same folder as the notebook
- 'malicious_phish.csv' - Base dataset
- 'PhishTank_2026.csv' - PhishTank list of reported phishing domains 
- 'top-1m.csv' - Tranco domain lists of legitimate websites 

2.2 Run the the data processing notebook 
Open the notebook, and run every cell from top to bottom 

The notebook will perform four things:
- Cleaning : It drops all of the missing and duplicated URLs which reduces the base dataset from 651,191 to 641,119 rows. 
- Reconcilation: It changes all of the schemas of all three datasets so they all share one common schema (url, label, type, source), furthermore Tranco will be downsized to only 100,000 rows to prevent source dominance, it also concatenates the three sources and also removes the duplicate URLs across the data sets. 
- Normalization: It normalize each URL so they all have the same structure by decoding percent-encoding, lowercasing the scheme, and also adds a default scheme if it is missing 
-Feature extraction: it applies the extract_features(url) function to all of the rows, which produces 16 numeric features that is used for modelling 

The notebook defines phishing as 1, and the other labels (benign, malware, defacement) as 0.

# Machine Learning & Model training
Environment setup
- set up conda packages in the shell
  ```
  conda env create -f environment.yml
  conda activate phishing
  ```
  To execute the testing file via the phishing path
- create the testing file
  + baseline.py
  + cluster.py
  + compare.py
  + crosssource.py
  + save the environment.yml file
 
- baseline.py and compare.py use 200,000 rows of a random sample, then split 80/20.
- crosssource.py trains on the ISCX and Tranco rows and then uses PhishTank to Test.
- cluster.py clusters only the phishing rows; K is set by the line K=4 near the top of the file, and the loop tries K=2 to K=8 before deciding to use K=4.

- Runtime for each execution takes about 5-15s 

- Push everything into github
