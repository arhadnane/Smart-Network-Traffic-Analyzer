# 🤖 Configuration Ollama pour Smart Network Traffic Analyzer

## Installation d'Ollama

1. **Télécharger Ollama** : [https://ollama.ai](https://ollama.ai)
2. **Installer Ollama** sur Windows
3. **Démarrer Ollama** (il démarre automatiquement un service sur localhost:11434)

## Installation du modèle recommandé

Ouvrez un terminal et exécutez :

```bash
# Modèle léger et rapide (recommandé)
ollama pull phi3:mini

# Alternatives si phi3:mini ne fonctionne pas
ollama pull llama3.2:1b
ollama pull qwen2:0.5b
```

## Vérification de l'installation

```bash
# Vérifier qu'Ollama fonctionne
curl http://localhost:11434/api/tags

# Tester le modèle
ollama run phi3:mini "Hello, how are you?"
```

## Configuration dans l'application

L'application se connecte automatiquement à Ollama sur `http://localhost:11434`.

### Fonctionnalités d'analyse Ollama

- ✅ **Analyse automatique** des IPs publiques quand vous cliquez sur une ligne
- ✅ **Évaluation de sécurité** (Faible/Moyen/Élevé)
- ✅ **Analyse de processus** (comportement typique du processus)
- ✅ **Recommandations** de sécurité si nécessaire
- ✅ **Support multilingue** (français par défaut)

### Interface utilisateur

Le panneau de droite affiche :
- 📋 **Détails de connexion** (IP, hostname, pays, processus, risque)
- 🤖 **Analyse Ollama** avec une évaluation intelligente

### Messages d'erreur courants

- `❌ Ollama service non disponible` → Vérifiez qu'Ollama est démarré
- `❌ Erreur d'analyse Ollama` → Vérifiez que le modèle phi3:mini est installé

## Modèles recommandés par taille

| Modèle | Taille | Vitesse | Qualité | Commande |
|--------|--------|---------|---------|----------|
| `phi3:mini` | ~2.3 GB | ⚡ Très rapide | ⭐⭐⭐ | `ollama pull phi3:mini` |
| `llama3.2:1b` | ~1.3 GB | ⚡⚡ Ultra rapide | ⭐⭐ | `ollama pull llama3.2:1b` |
| `qwen2:0.5b` | ~0.5 GB | ⚡⚡⚡ Instantané | ⭐ | `ollama pull qwen2:0.5b` |

## Dépannage

1. **Port 11434 occupé** → Redémarrez Ollama
2. **Modèle non trouvé** → Exécutez `ollama pull phi3:mini`
3. **Timeout de connexion** → Vérifiez que Ollama fonctionne avec `ollama list`

## Exemple d'analyse

```
📡 Connexion vers 142.250.185.142 (Google)
🔍 Analyse Ollama :

**Résumé** : Connexion vers Google (YouTube/Gmail)
**Sécurité** : Faible risque - service légitime
**Processus** : Chrome navigue vers des services Google
**Recommandations** : Aucune action requise
```
