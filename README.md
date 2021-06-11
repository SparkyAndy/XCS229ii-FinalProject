# XCS229ii-FinalProject - Classifying Computer Processes in the DARPA OpTC dataset

## Contents

This repo contains the deliverables (documents) for my Machine Learning (ML) project for the course
[XCS229ii](https://online.stanford.edu/courses/xcs229ii-machine-learning-strategy-and-intro-reinforcement-learning) (cohort 003):

- **ProjectProposalClassifyingComputerProcessesAndrewVeal.pdf** is the first deliverable - the project proposal

- **LiteratureReviewClassifyingComputerProcessesAndrewVeal.pdf** is the second deliverable - the literature review

- **ExperimentalProtocolClassifyingComputerProcessesAndrewVealFINAL.pdf** is the third deliverable - the experimental protocol

- **FinalPaperClassifyingComputerProcessesAndrewVealFINAL.pdf** is the final deliverable - the final paper

It also contains the guidance documents for each deliverable - what the distribution of marks is and what each section of the document should cover - these were written by Sebastian Hurubaru and are shared with his permission:

- **xcs229ii_project_proposal.pdf** 

- **xcs229ii_literature_review.pdf**

- **xcs229ii_experimental_protocol.pdf**

- **xcs229ii_final_paper.pdf**

I have included the slides for a short 5 minute 'lightning' talk I gave to Course Facilitators (CFs) and fellow learners in cohort 003 (15 March 2021 - 29 May 2021):

- **XCS229iiProjectTalkForStanford15May2021StopPress.pdf**

I have also included a few starter Jupyter notebooks for processing the Machine Learning (ML) dataset:

- `ClassifyingComputerProcessesDarpaOpTCBaselineModel.ipynb` - basic starter notebook

- `CCPDOpTC_labels.ipynb` - basic notebook for navigating the labels.csv

The ground truth `labels.csv` file contains the details for the malicious events derived from the _OpTC Red Team Ground Truth_ [6].

Unfortunately, I am not currently able to release the derived dataset `darpa_data_revised` (but you can make your own from the raw data on github/google drive - details of the Extract, Transform and Load (ETL) pipeline are given in the experimental protocol and final paper).

## GitHub

https://github.com/ageron/handson-ml2 

> **Machine Learning Notebooks** "This project aims at teaching you the fundamentals of Machine Learning in python. It contains the example code and solutions to the exercises in the second edition of my O'Reilly book _Hands-on Machine Learning with Scikit-Learn, Keras and TensorFlow_"

## References

[1] Chris Albon. 2018. _Machine Learning with Python Cookbook: Practical Solutions from Preprocessing to Deep Learning._ O'Reilly Media, Inc. CA

[2] Md. Monowar Anjum, Shahrear Iqbal and Benoit Hamelin. 2021. _Analysing the Usefulness of the DARPA OpTC Dataset in Cyber Threat Detection Research._ **arXiv:** 2103.03080v2. Retrieved from https://arxiv.org/abs/2103.03080 Accepted for _ACM Symposium on Access Control Models and Technologies (SACMAT)_, 16-18 June, 2021, Barcelona, Spain (virtual event). ACM Inc., New York, NY. **DOI:**  https://doi.org/10.1145/3450569.3463573

[3] **Artificial Intelligence Professional Program** retrieved from  https://online.stanford.edu/programs/artificial-intelligence-professional-program

[4] DARPA. 2020. _Operationally Transparent Cyber (OpTC) Data Release. README._ Retrieved from http://github.com/FiveDirections/OpTC-data

[5] DARPA. 2020. _Operationally Transparent Cyber (OpTC) Data Release._ Retrieved from https://drive.google.com/drive/u/0/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa

[6] DARPA. 2020. _OpTC Red Team Ground Truth._ Retrieved April 7, 2021 from https://github.com/FiveDirections/OpTC-data/blob/master/OpTCRedTeamGroundTruth.pdf

[7] Edsger Dijkstra. 1968. _Go To Statement Considered Harmful._ Communications of the ACM. 11 (3): 147–148. **DOI:** 10.1145/362929.362947. 

[8] Michael Freeman and Joel Ross. 2019. _Programming Skills for Data Science: Start Writing Code to Wrangle, Analyse, and Visualize Data with R_ Addison-Wesley Boston, MA **ISBN-13:** 978-0-13-513310-1

[9] Aurelien Geron. 2019. _Hands-On Machine Learning with Scikit-Learn, Keras & TensorFlow: Concepts, Tools, and Techniques to Build Intelligent Systems._ O'Reilly Media, Inc. CA https://oreilly.com/library/view/hands-on-machine-learning/9781492032632/

[10] David J. Hand. 2009. _Mismatched Models, Wrong Results, and Dreadful Decisions._ Keynote at _15th ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD 2009)_, June, 2009 Paris, France recorded June 2009, published September 14, 2009 http://videolectures.net/kdd09_hand_mmwrdd/ (video) http://videolectures.net/site/normal_dl/tag=45840/kdd09_hand_mmwrdd_01.pdf (slides)

[11] David J. Hand. 2009. _Measuring classifier performance: a coherent alternative to the area under the ROC curve._ Mach Learn, 77 (2009), 103–123. DOI: https://doi.org/10.1007/s10994-009-5119-5

[12] labels.csv retrieved from (need approval)

[13] **Machine Learning Strategy and Intro to Reinforcement Learning** (XCS229ii) retrieved from https://online.stanford.edu/courses/xcs229ii-machine-learning-strategy-and-intro-reinforcement-learning

[14] Andrew Ng. 2018. _Machine Learning Yearning: Technical Strategy for AI Engineers, In the Era of Deep Learning._ Draft Version. Retrieved May 6, 2021 from https://www.deeplearning.ai/programs/

[15] **Stanford Center for  Professional Development (SCPD)** retrieved from https://scpd.stanford.edu/

[16] Charles Wheelus, Elias Bou-Harb and Xingquan Zhu. 2018. _Tackling Class Imbalance in Cyber Security Datasets._ In _Proceedings of the 2018 IEEE International Conference on Information Reuse and Integration (IRI)_, 6-9 July, 2018, Salt Lake City, UT, USA. IEEE Xplore, 229-232. https://doi.org/10.1109/IRI.2018.00041