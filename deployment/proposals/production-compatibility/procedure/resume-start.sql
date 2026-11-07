INSERT INTO d1_cveharbor_repair_receipts(id,payload) SELECT 'resume-started',payload FROM d1_cveharbor_repair_receipts WHERE id='resume-intent';
