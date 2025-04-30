from transformers import AutoTokenizer, AutoModelForSequenceClassification
import tensorflow as tf
import os

class ModelConfig:
    def __init__(self):
        # Base paths
        self.model_path = os.path.dirname(os.path.abspath(__file__))
        
        # Model configurations
        self.models = {
            'pattern_recognition': {
                'name': 'pattern_classifier',
                'type': 'transformer',
                'model_id': 'microsoft/codebert-base',
                'task': 'text-classification',
                'labels': ['safe', 'suspicious', 'malicious']
            },
            'anomaly_detection': {
                'name': 'anomaly_detector',
                'type': 'tensorflow',
                'architecture': 'isolation_forest',
                'features': [
                    'request_length',
                    'special_chars_ratio',
                    'entropy',
                    'param_count'
                ]
            },
            'threat_classification': {
                'name': 'threat_classifier',
                'type': 'transformer',
                'model_id': 'distilbert-base-uncased',
                'task': 'text-classification',
                'labels': ['low', 'medium', 'high', 'critical']
            }
        }
    
    def load_transformer_model(self, model_type):
        """Load a transformer model for the specified type"""
        config = self.models.get(model_type)
        if not config or config['type'] != 'transformer':
            raise ValueError(f"Invalid model type: {model_type}")
        
        try:
            tokenizer = AutoTokenizer.from_pretrained(config['model_id'])
            model = AutoModelForSequenceClassification.from_pretrained(
                config['model_id'],
                num_labels=len(config['labels'])
            )
            return {'model': model, 'tokenizer': tokenizer, 'labels': config['labels']}
        except Exception as e:
            print(f"Error loading transformer model: {str(e)}")
            return None
    
    def load_tensorflow_model(self, model_type):
        """Load a TensorFlow model for the specified type"""
        config = self.models.get(model_type)
        if not config or config['type'] != 'tensorflow':
            raise ValueError(f"Invalid model type: {model_type}")
        
        try:
            if config['architecture'] == 'isolation_forest':
                from sklearn.ensemble import IsolationForest
                model = IsolationForest(
                    n_estimators=100,
                    contamination=0.1,
                    random_state=42
                )
                return {'model': model, 'features': config['features']}
        except Exception as e:
            print(f"Error loading TensorFlow model: {str(e)}")
            return None
    
    def get_model_info(self, model_type):
        """Get model configuration information"""
        return self.models.get(model_type)

# Initialize default configuration
default_config = ModelConfig()
