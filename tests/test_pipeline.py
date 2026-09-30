import unittest
import test_data
from abh.pipeline import FindingPipeline,CHECKS
from abh.data import DataError

class PipelineTests(unittest.TestCase):
    add = test_data.DataTests.add
    evidence = test_data.DataTests.evidence
    def setUp(self):
        test_data.DataTests.setUp(self);self.pipeline=FindingPipeline(self.db)
    def validate(self):
        return self.pipeline.review(self.finding['id'],'validated',{key:True for key in CHECKS},'Human inspected synthetic evidence')
    def test_validation_requires_raw_and_all_checks(self):
        with self.assertRaises(DataError):self.validate()
        self.evidence(origin='generated')
        with self.assertRaises(DataError):self.validate()
        self.evidence();self.validate()
        self.assertEqual(self.pipeline.show(self.finding['id'])['status'],'validated')
    def test_evidence_change_invalidates_validation(self):
        self.evidence();self.validate();self.evidence(content=b'new')
        self.assertEqual(self.pipeline.show(self.finding['id'])['status'],'needs_validation')
    def test_report_review_and_no_submission(self):
        evidence=self.evidence();self.validate()
        report=self.pipeline.draft(self.finding['id'],'Draft',[{'id':'q1','label':'Exact question?','answer':'Manually reviewed statement','evidence_ids':[evidence['id']]}])
        result=self.pipeline.approve_report(report['id'])
        self.assertEqual(result['payload']['decision'],'approved')
        self.assertFalse(result['payload']['submission_enabled'])
        with self.assertRaises(DataError):self.pipeline.approve_report(report['id'])
    def test_unanswered_report_cannot_be_approved(self):
        evidence=self.evidence();self.validate()
        report=self.pipeline.draft(self.finding['id'],'Draft',[{'id':'q1','label':'Exact question?','answer':None,'evidence_ids':[evidence['id']]}])
        with self.assertRaises(DataError):self.pipeline.approve_report(report['id'])
    def test_duplicate_candidates_and_human_decision(self):
        other=self.add('finding',dict(self.finding['payload']),self.observation)
        self.assertIn(other['id'],self.pipeline.duplicates(self.finding['id'])['candidate_matches'])
        self.pipeline.review(self.finding['id'],'duplicate',{key:False for key in CHECKS},'Same supplied candidate',duplicate_of=other['id'])
        self.assertEqual(self.pipeline.show(self.finding['id'])['status'],'duplicate')
    def test_rejection_invalidates_draft_workflow(self):
        evidence=self.evidence();self.validate()
        report=self.pipeline.draft(self.finding['id'],'Draft',[{'id':'q','label':'Impact','answer':'Synthetic','evidence_ids':[evidence['id']]}])
        self.pipeline.review(self.finding['id'],'false_positive',{key:False for key in CHECKS},'Contradictory evidence')
        with self.assertRaises(DataError):self.pipeline.approve_report(report['id'])
