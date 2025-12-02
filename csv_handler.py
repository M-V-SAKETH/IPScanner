"""
CSV Handler Module
Handles all CSV file operations with optimized batch saving
"""

import pandas as pd
from loggerConfig import logger
from config import INPUT_FILE, CSV_ENCODING, BATCH_SAVE_INTERVAL, FORCE_SAVE_INTERVAL


class CSVHandler:
    """Handler for CSV file operations with batch saving support"""
    
    def __init__(self, file_path=INPUT_FILE):
        self.file_path = file_path
        self.save_counter = 0
        
    def load_csv(self):
        """
        Load CSV file with error handling
        
        Returns:
            tuple: (dataframe: pd.DataFrame or None, error: str or None)
        """
        try:
            logger.info(f"Loading CSV file: {self.file_path}")
            df = pd.read_csv(self.file_path, encoding=CSV_ENCODING, dtype=str)
            logger.info(f"Loaded {len(df)} rows with columns: {list(df.columns)}")
            return df, None
        except FileNotFoundError:
            error_msg = f"CSV file '{self.file_path}' not found!"
            logger.error(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"Error loading CSV file: {str(e)}"
            logger.error(error_msg)
            return None, error_msg
    
    def save_csv(self, df, force=False):
        """
        Save DataFrame to CSV file
        
        Args:
            df: DataFrame to save
            force: If True, save immediately regardless of counter
            
        Returns:
            bool: True if saved, False otherwise
        """
        try:
            df.to_csv(self.file_path, index=False, encoding=CSV_ENCODING)
            self.save_counter = 0
            logger.debug(f"Progress saved to {self.file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save progress: {str(e)}")
            return False
    
    def should_save(self, force=False):
        """
        Determine if CSV should be saved based on batch interval
        
        Args:
            force: Force save regardless of counter
            
        Returns:
            bool: True if should save
        """
        if force:
            return True
        
        self.save_counter += 1
        
        # Save every BATCH_SAVE_INTERVAL items
        if self.save_counter >= BATCH_SAVE_INTERVAL:
            return True
        
        # Force save every FORCE_SAVE_INTERVAL items regardless
        if self.save_counter % FORCE_SAVE_INTERVAL == 0:
            return True
        
        return False
    
    def update_row(self, df, index, result_dict):
        """
        Update a single row in the DataFrame
        
        Args:
            df: DataFrame to update
            index: Row index to update
            result_dict: Dictionary with column names and values
        """
        for key, value in result_dict.items():
            df.at[index, key] = str(value)

