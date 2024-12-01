import pandas as pd
import numpy as np
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import re
from datetime import datetime

def parse_log_line(line):
    """Parse log untuk SQL Injection dan Brute Force dengan pengecekan log normal yang lebih baik"""
    # Pattern untuk log normal
    normal_patterns = [
        r'session (opened|closed) for user',
        r'New session',
        r'COMMAND=/usr',
        r'New seat',
        r'PAM adding faulty module',
        r'ROOT LOGIN'
    ]
    
    # Pattern untuk Brute Force
    brute_force_pattern = re.compile(r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)')
    
    # Pattern untuk SQL Injection
    sql_pattern = re.compile(r'.*SQL Injection.*|.*Input contains.*OR 1=1.*|.*SELECT \* FROM users WHERE.*')
    
    # Ekstrak timestamp
    timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if not timestamp_match:
        return None
        
    timestamp = timestamp_match.group(1)
    
    # Deteksi Brute Force
    brute_match = brute_force_pattern.search(line)
    if brute_match:
        username, ip = brute_match.groups()
        return {
            'timestamp': timestamp,
            'ip': ip,
            'username': username,
            'raw_log': line.strip(),
            'attack_type': 'Brute Force',
            'failed_attempt': 1
        }
    
    # Deteksi SQL Injection
    if sql_pattern.search(line):
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        ip = ip_match.group(1) if ip_match else 'unknown'
        return {
            'timestamp': timestamp,
            'ip': ip,
            'username': 'none',
            'raw_log': line.strip(),
            'attack_type': 'SQL Injection',
            'failed_attempt': 0
        }
    
    # Verifikasi log normal
    is_normal = any(re.search(pattern, line) for pattern in normal_patterns)
    if is_normal:
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        return {
            'timestamp': timestamp,
            'ip': ip_match.group(1) if ip_match else 'localhost',
            'username': 'system',
            'raw_log': line.strip(),
            'attack_type': 'Normal',
            'failed_attempt': 0
        }
    
    return None

def process_logs(file_paths):
    all_data = []
    ip_failed_attempts = {}
    
    for file_path in file_paths:
        print(f"\nMemproses file: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    parsed = parse_log_line(line)
                    if parsed:
                        ip = parsed['ip']
                        if parsed['failed_attempt'] == 1:
                            ip_failed_attempts[ip] = ip_failed_attempts.get(ip, 0) + 1
                        parsed['total_failed_attempts'] = ip_failed_attempts.get(ip, 0)
                        parsed['source_file'] = file_path.split('/')[-1]
                        all_data.append(parsed)
        except Exception as e:
            print(f"Error membaca file {file_path}: {str(e)}")
    
    return pd.DataFrame(all_data)

def detect_attacks(df, brute_force_threshold=3):
    """Deteksi serangan dengan penanganan log normal yang lebih baik"""
    # Inisialisasi kolom is_attack sebagai False
    df['is_attack'] = False
    
    # Deteksi Brute Force
    brute_force_mask = (df['attack_type'] == 'Brute Force') & \
                      (df['total_failed_attempts'] >= brute_force_threshold)
    
    # Deteksi SQL Injection
    sql_injection_mask = df['attack_type'] == 'SQL Injection'
    
    # Gabungkan deteksi
    df.loc[brute_force_mask | sql_injection_mask, 'is_attack'] = True
    
    return df

def calculate_metrics(df):
    """Menghitung metrik akurasi deteksi"""
    # Hitung total log
    total_logs = len(df)
    
    # Hitung distribusi jenis log
    log_distribution = df['attack_type'].value_counts()
    
    # Hitung akurasi per kategori
    accuracy_metrics = {
        'Normal': {
            'total': len(df[df['attack_type'] == 'Normal']),
            'correct': len(df[(df['attack_type'] == 'Normal') & (df['is_attack'] == False)]),
        },
        'SQL Injection': {
            'total': len(df[df['attack_type'] == 'SQL Injection']),
            'correct': len(df[(df['attack_type'] == 'SQL Injection') & (df['is_attack'] == True)]),
        },
        'Brute Force': {
            'total': len(df[df['attack_type'] == 'Brute Force']),
            'correct': len(df[(df['attack_type'] == 'Brute Force') & (df['is_attack'] == True)]),
        }
    }
    
    # Hitung akurasi keseluruhan
    total_correct = sum(metric['correct'] for metric in accuracy_metrics.values())
    overall_accuracy = (total_correct / total_logs) * 100 if total_logs > 0 else 0
    
    # Tambahan analisis IP dan serangan
    ip_analysis = {
        'unique_ips': df['ip'].nunique(),
        'top_attacker_ips': df[df['is_attack'] == True]['ip'].value_counts().head(5).to_dict(),
        'attacks_per_ip': df[df['is_attack'] == True].groupby('ip')['attack_type'].value_counts().to_dict()
    }
    
    attack_analysis = {
        'attack_timeline': df[df['is_attack'] == True].groupby(['timestamp', 'attack_type']).size().to_dict(),
        'attack_patterns': df[df['is_attack'] == True]['attack_type'].value_counts().to_dict()
    }
    
    return {
        'total_logs': total_logs,
        'distribution': log_distribution,
        'accuracy_metrics': accuracy_metrics,
        'overall_accuracy': overall_accuracy,
        'ip_analysis': ip_analysis,
        'attack_analysis': attack_analysis
    }

def create_summary_tables(metrics, attack_characteristics):
    """Membuat tabel ringkasan hasil evaluasi"""
    
    # Tabel 1: Distribusi Log
    distribution_data = {
        'Jenis Log': metrics['distribution'].index,
        'Jumlah': metrics['distribution'].values,
        'Persentase (%)': [(count/metrics['total_logs'])*100 for count in metrics['distribution'].values]
    }
    distribution_table = pd.DataFrame(distribution_data)
    
    # Tabel 2: Metrik Akurasi
    accuracy_data = []
    for category, metric in metrics['accuracy_metrics'].items():
        if metric['total'] > 0:
            accuracy = (metric['correct'] / metric['total']) * 100
            accuracy_data.append({
                'Kategori': category,
                'Total Log': metric['total'],
                'Terdeteksi Benar': metric['correct'],
                'Akurasi (%)': accuracy
            })
    accuracy_table = pd.DataFrame(accuracy_data)
    
    # Tabel 3: Karakteristik Serangan
    characteristics_data = {
        'Jenis Serangan': ['SQL Injection', 'Brute Force'],
        'Jumlah Pattern': [
            len(attack_characteristics['sql_patterns']),
            len(attack_characteristics['brute_force_ips'])
        ]
    }
    characteristics_table = pd.DataFrame(characteristics_data)
    
    # Tabel 4: Analisis IP
    ip_data = []
    for ip, count in metrics['ip_analysis']['top_attacker_ips'].items():
        attack_types = []
        for (attacker_ip, attack_type), freq in metrics['ip_analysis']['attacks_per_ip'].items():
            if attacker_ip == ip:
                attack_types.append(f"{attack_type}: {freq}")
        
        ip_data.append({
            'IP Address': ip,
            'Jumlah Serangan': count,
            'Jenis Serangan': ', '.join(attack_types)
        })
    ip_analysis_table = pd.DataFrame(ip_data)
    
    return distribution_table, accuracy_table, characteristics_table, ip_analysis_table

try:
    # Pisahkan file dataset dan testing
    dataset_files = [
        'd:/Kulia/MSIB/Perkuliahan MSIB/Projek/log_sql.log',
        'd:/Kulia/MSIB/Perkuliahan MSIB/Projek/log_brutforce.log'
    ]
    
    test_files = [
        'd:/Kulia/MSIB/Perkuliahan MSIB/Projek/tidak.log'
    ]
    
    # Proses dataset untuk training
    print("Memproses file dataset...")
    df_train = process_logs(dataset_files)
    df_train = detect_attacks(df_train)
    
    # Proses file testing
    print("\nMemproses file testing...")
    df_test = process_logs(test_files)
    df_test = detect_attacks(df_test)
    
    # Statistik untuk data testing
    print("\nHasil Analisis Data Testing:")
    test_metrics = calculate_metrics(df_test)
    
    print(f"\nTotal Log Testing Dianalisis: {test_metrics['total_logs']}")
    print("\nDistribusi Jenis Log Testing:")
    for log_type, count in test_metrics['distribution'].items():
        percentage = (count / test_metrics['total_logs']) * 100
        print(f"{log_type}: {count} ({percentage:.2f}%)")
    
    # Hitung metrik untuk dataset training
    train_metrics = calculate_metrics(df_train)
    
    # Karakteristik serangan dari data training
    attack_characteristics = {
        'sql_patterns': [
            r'.*SQL Injection.*',
            r'.*Input contains.*OR 1=1.*',
            r'.*SELECT \* FROM users WHERE.*'
        ],
        'brute_force_ips': set(df_train[df_train['attack_type'] == 'Brute Force']['ip'].unique())
    }
    
    # Buat tabel ringkasan terpisah untuk training dan testing
    print("\n=== RINGKASAN HASIL EVALUASI ===")
    
    print("\nA. HASIL DATASET TRAINING:")
    distribution_table_train, accuracy_table_train, characteristics_table, ip_analysis_table = create_summary_tables(train_metrics, attack_characteristics)
    print("\n1. Distribusi Log Training:")
    print(distribution_table_train.to_string(index=False))
    
    print("\n2. Top 5 IP Penyerang:")
    print(ip_analysis_table.to_string(index=False))
    
    print("\n3. Ringkasan Serangan per Jenis:")
    for attack_type, count in test_metrics['attack_analysis']['attack_patterns'].items():
        print(f"{attack_type}: {count} serangan")
    
    print("\nB. HASIL DATA TESTING:")
    distribution_table_test, accuracy_table_test, characteristics_table_test, ip_analysis_table_test = create_summary_tables(test_metrics, attack_characteristics)
    print("\n1. Distribusi Log Testing:")
    print(distribution_table_test.to_string(index=False))
    
    print("\n2. Metrik Akurasi Testing:")
    print(accuracy_table_test.to_string(index=False))
    
    print("\n3. Analisis IP Testing:")
    print(ip_analysis_table_test.to_string(index=False))
    
    # Simpan hasil ke Excel dengan sheet terpisah untuk training dan testing
    with pd.ExcelWriter('hasil_evaluasi_model.xlsx') as writer:
        distribution_table_train.to_excel(writer, sheet_name='Distribusi Log Training', index=False)
        accuracy_table_train.to_excel(writer, sheet_name='Metrik Akurasi Training', index=False)
        distribution_table_test.to_excel(writer, sheet_name='Distribusi Log Testing', index=False)
        accuracy_table_test.to_excel(writer, sheet_name='Metrik Akurasi Testing', index=False)
        characteristics_table.to_excel(writer, sheet_name='Karakteristik Serangan', index=False)
        ip_analysis_table.to_excel(writer, sheet_name='Analisis IP Penyerang', index=False)
    
    print("\nHasil evaluasi telah disimpan ke 'hasil_evaluasi_model.xlsx'")

except Exception as e:
    print(f"Error: {str(e)}")