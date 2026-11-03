"""
IntentClassifier — Multilingual Deletion Intent Detection.
Supports: en, es, fr, de, pt, it, nl, tr, ru, ja, zh, ko, hi, ar.
Handles Unicode NFKC normalization, negation windows, non-deletion overrides,
and mixed-request precedence.
"""
import re
import unicodedata
from typing import Dict, Any, Optional, List
from .common import sha256_hex


class IntentResult:
    def __init__(self, authorized: bool, confidence: float, intent: str,
                 reasons: List[str], language: Optional[str] = None,
                 negation_detected: bool = False, partial_scope: bool = False):
        self.authorized = authorized
        self.confidence = confidence
        self.intent = intent
        self.reasons = reasons
        self.language = language
        self.negation_detected = negation_detected
        self.partial_scope = partial_scope


DELETION_VERBS = {
    "en": ["delete", "erase", "remove", "close", "destroy", "purge", "wipe", "expunge", "gone", "deleted", "removed", "closed", "cancellation"],
    "es": ["eliminar", "borrar", "suprimir", "cancelar", "destruir", "cerrar", "baja", "eliminación", "elimine", "eliminen", "borre", "borren", "cancele", "cancelen"],
    "fr": ["supprimer", "effacer", "fermer", "détruire", "annuler", "suppression", "effacement", "supprimez", "effacez", "fermez"],
    "de": ["löschen", "entfernen", "schließen", "zerstören", "tilgen", "löschung", "lösche", "löscht"],
    "pt": ["excluir", "apagar", "remover", "cancelar", "destruir", "fechar", "exclusão", "exclua", "excluam", "apague", "apaguem"],
    "it": ["cancellare", "eliminare", "rimuovere", "chiudere", "distruggere", "cancellazione", "cancelli", "cancelliate", "elimini"],
    "nl": ["verwijderen", "wissen", "sluiten", "vernietigen", "verwijdering"],
    "tr": ["sil", "silmek", "silme", "silin", "siliniz", "silinsin", "kaldır", "kapat", "yok et", "hesabımı sil"],
    "ru": ["удалить", "уничтожить", "стереть", "закрыть", "удаление", "ликвидировать", "удалите"],
    "ja": ["削除", "消去", "削除する", "消去する", "アカウント削除", "解約", "退会"],
    "zh": ["删除", "销毁", "注销", "抹掉", "清除", "注销账户", "删除账户"],
    "ko": ["삭제", "영구 삭제", "삭제를", "삭제해", "탈퇴", "삭제요청", "삭제 요청", "계정 삭제", "회원탈퇴", "지워"],
    "hi": ["हटाएं", "मिटाएं", "डिलीट", "हटाना", "मिटाना", "खाता हटाएं", "हटा"],
    "ar": ["حذف", "مسح", "إزالة", "إلغاء", "إغلاق الحساب", "محو"],
}

NON_DELETION_KEYWORDS = {
    "en": [
        "access", "rectify", "rectification", "correct", "update", "export", "download",
        "portability", "opt-out", "marketing", "unsubscribe", "password", "reset password",
        "login assistance", "unlock"
    ],
    "es": [
        "acceso", "corregir", "rectificar", "rectificación", "actualizar", "exportar",
        "descargar", "portabilidad", "cancelar suscripción", "opt-out", "contraseña"
    ],
    "fr": [
        "accès", "corriger", "rectifier", "rectification", "mettre à jour", "exporter",
        "télécharger", "portabilité", "se désabonner", "mot de passe"
    ],
    "de": [
        "zugang", "auskunft", "korrigieren", "berichtigen", "berichtigung", "aktualisieren",
        "exportieren", "herunterladen", "portabilität", "abbestellen", "passwort"
    ],
    "pt": [
        "acesso", "corrigir", "retificar", "retificação", "atualizar", "exportar",
        "baixar", "portabilidade", "cancelar inscrição", "senha"
    ],
    "it": [
        "accesso", "correggere", "rettificare", "rettifica", "aggiornare", "esportare",
        "scaricare", "portabilità", "disdiciti", "password"
    ],
    "nl": [
        "toegang", "inzage", "corrigeren", "rectificeren", "bijwerken", "exporteren",
        "downloaden", "portabiliteit", "uitschrijven", "wachtwoord"
    ],
    "tr": [
        "erişim", "düzelt", "düzeltme", "güncelle", "dışa aktar", "indir", "abonelikten çık", "şifre"
    ],
    "ru": [
        "доступ", "исправить", "исправление", "обновить", "экспорт", "выгрузить", "отписаться", "пароль"
    ],
    "ja": [
        "アクセス", "確認", "修正", "訂正", "更新", "エクスポート", "ダウンロード", "ポータビリティ", "オプトアウト", "パスワード"
    ],
    "zh": [
        "访问", "查阅", "修正", "更正", "更新", "导出", "下载", "数据可携", "退订", "密码"
    ],
    "ko": [
        "조회", "확인", "열람", "수정", "정정", "업데이트", "내보내기", "다운로드", "수신거부", "비밀번호"
    ],
    "hi": [
        "पहुंच", "देखें", "सुधार", "अपडेट", "एक्सपोर्ट", "डाउनलोड", "पासवर्ड"
    ],
    "ar": [
        "وصول", "اطلاع", "تصحيح", "تعديل", "تحديث", "تصدير", "تنزيل", "إلغاء الاشتراك", "كلمة المرور"
    ],
}

NEGATION_MARKERS = {
    "en": ["not", "don't", "do not", "never", "no", "without", "none", "nothing"],
    "es": ["no", "nunca", "jamás", "ningún", "ninguna", "nada", "sin"],
    "fr": ["ne", "pas", "jamais", "aucun", "aucune", "rien", "non", "sans"],
    "de": ["nicht", "niemals", "nie", "kein", "keine", "nichts", "ohne"],
    "pt": ["não", "nunca", "jamais", "nenhum", "nenhuma", "nada", "sem"],
    "it": ["non", "mai", "nessuno", "nessuna", "nulla", "senza"],
    "nl": ["niet", "nooit", "geen", "niks", "zonder"],
    "tr": ["değil", "asla", "hayır", "yok", "etmeyin", "silmeyin"],
    "ru": ["не", "нет", "никогда", "никакой", "не удалять"],
    "ja": ["しない", "してはいけない", "削除しない", "削除しないで", "ない"],
    "zh": ["不", "不要", "请勿", "非", "别", "不删除"],
    "ko": ["안", "않", "하지 마", "삭제하지", "마세요", "아니"],
    "hi": ["नहीं", "मत", "ना"],
    "ar": ["لا", "لن", "ليس", "عدم", "دون"],
}

HYPOTHETICAL_MARKERS = {
    "en": ["what happens if", "what if", "if i delete", "should i", "would you", "how do i", "can i"],
    "es": ["qué pasa si", "qué sucede si", "si elimino", "debería", "cómo puedo", "puedo"],
    "fr": ["que se passe-t-il si", "que se passe-t-il", "si je supprime", "devrais-je", "comment puis-je"],
    "de": ["was passiert wenn", "was ist wenn", "wenn ich lösche", "sollte ich", "wie kann ich"],
    "pt": ["o que acontece se", "e se", "se eu excluir", "deveria", "como posso"],
    "it": ["cosa succede se", "e se", "se cancello", "dovrei", "come posso"],
    "nl": ["wat gebeurt er als", "wat als", "als ik verwijder", "moet ik", "hoe kan ik"],
    "tr": ["ne olur", "silsem ne olur", "nasıl yapabilirim"],
    "ru": ["что произойдет если", "что если", "как мне", "могу ли я"],
    "ja": ["もし削除したら", "削除したらどうなる", "どうなりますか", "どうすれば"],
    "zh": ["如果我删除", "会发生什么", "怎样才能", "如何删除"],
    "ko": ["삭제하면 어떻게", "만약 삭제", "어떻게 해야"],
    "hi": ["क्या होगा अगर", "कैसे करें"],
    "ar": ["ماذا يحدث إذا", "كيف يمكنني"],
}

PARTIAL_SCOPE_MARKERS = {
    "en": ["marketing only", "analytics only", "just the newsletter", "only promotional", "stop sending emails"],
    "es": ["solo marketing", "solo correos", "únicamente publicidad"],
    "fr": ["marketing seulement", "seulement les e-mails", "uniquement newsletter"],
    "de": ["nur marketing", "nur newsletter", "nur werbung"],
    "pt": ["apenas marketing", "somente emails", "apenas newsletter"],
    "it": ["solo marketing", "solo newsletter", "solo promozioni"],
    "nl": ["alleen marketing", "alleen nieuwsbrief"],
    "tr": ["sadece pazarlama", "sadece bülten"],
    "ru": ["только маркетинг", "только рассылка"],
    "ja": ["マーケティングのみ", "メルマガのみ"],
    "zh": ["仅营销", "仅退订邮件", "只退订"],
    "ko": ["마케팅만", "광고만", "뉴스레터만"],
    "hi": ["केवल मार्केटिंग"],
    "ar": ["فقط التسويق"],
}

LANGUAGE_DETECTION_PATTERNS = {
    "ja": r"[\u3040-\u309f\u30a0-\u30ff]",
    "zh": r"[\u4e00-\u9fff]",
    "ko": r"[\uac00-\ud7af]",
    "ru": r"[\u0400-\u04ff]",
    "ar": r"[\u0600-\u06ff]",
    "hi": r"[\u0900-\u097f]",
    "tr": r"\b(ve|bir|bu|da|de|için|ile|hesap|lütfen|silin|verilerimi)\b",
    "es": r"\b(el|la|los|las|que|es|si|no|por favor|gracias|cuenta)\b",
    "fr": r"\b(le|la|les|que|est|si|ne|pas|je|vous|s'il|vous plaît|merci|compte)\b",
    "pt": r"\b(o|a|os|as|que|é|se|não|por favor|obrigado|conta)\b",
    "de": r"\b(der|die|das|und|ist|nicht|bitte|danke|konto)\b",
    "it": r"\b(il|la|le|che|è|non|per favore|grazie|conto)\b",
    "nl": r"\b(het|de|en|is|niet|alstublieft|dank|account)\b",
}

def detect_language(text: str) -> str:
    for lang in ["ja", "ko", "zh", "ru", "ar", "hi"]:
        if re.search(LANGUAGE_DETECTION_PATTERNS[lang], text):
            return lang
    text_lower = text.lower()
    scores = {}
    for lang, pattern in LANGUAGE_DETECTION_PATTERNS.items():
        if lang in ["ja", "ko", "zh", "ru", "ar", "hi"]:
            continue
        matches = len(re.findall(pattern, text_lower))
        if matches > 0:
            scores[lang] = matches
    if scores:
        best = max(scores, key=scores.get)
        if scores[best] >= 1:
            return best
    return "en"

def _count_keywords(text_lower: str, keywords: List[str]) -> int:
    count = 0
    for kw in keywords:
        if any(ord(c) > 127 for c in kw):
            if kw in text_lower:
                count += 1
        else:
            if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                count += 1
    return count

ALL_DELETION_VERBS = set()
for _verbs in DELETION_VERBS.values():
    ALL_DELETION_VERBS.update(_verbs)

COMMON_STEMS = [
    "delet", "eras", "remov", "clos", "destroy", "purge", "wipe", "expung",
    "supprim", "effac", "ferm", "annul", "exclu", "apag", "elimin", "borr",
    "suprim", "tilg", "vernicht", "wisch", "cancell", "sil", "удалит", "삭제",
    "탈퇴", "注销", "删除", "हटा"
]

def _find_negation_in_window(text_lower: str, negation_words: List[str], window_size: int = 5) -> bool:
    tokens = re.findall(r'\b\w+\b|[^\w\s]', text_lower, re.UNICODE)
    for i, token in enumerate(tokens):
        is_del = (token in ALL_DELETION_VERBS) or any(s in token for s in COMMON_STEMS)
        if not is_del:
            for v in ALL_DELETION_VERBS:
                if any(ord(c) > 127 for c in v) and v in token:
                    is_del = True
                    break
        if is_del:
            start = max(0, i - window_size)
            end = min(len(tokens), i + window_size + 1)
            window = tokens[start:end]
            for neg in negation_words:
                if neg in window:
                    return True
    return False

class IntentClassifier:
    def __init__(self, llm_enabled: bool = False, llm_cache: Optional[Dict[str, Any]] = None):
        self.llm_enabled = llm_enabled
        self.llm_cache = llm_cache if llm_cache is not None else {}

    def classify(self, request_text: str) -> IntentResult:
        if not request_text or not request_text.strip():
            return IntentResult(
                authorized=False, confidence=1.0, intent="NON_DELETION",
                reasons=["Empty request text"], language="en",
            )

        # Normalize Unicode using NFKC
        text = unicodedata.normalize("NFKC", request_text).strip()
        text_lower = text.lower()
        lang = detect_language(text)

        reasons = []
        negation_detected = False
        partial_scope = False
        hypothetical = False

        # 1. Check hypothetical markers
        hyp_markers = HYPOTHETICAL_MARKERS.get(lang, []) + HYPOTHETICAL_MARKERS.get("en", [])
        for marker in hyp_markers:
            if re.search(r'(?<!\w)' + re.escape(marker) + r'(?!\w)', text_lower):
                hypothetical = True
                reasons.append(f"Hypothetical/question marker detected: {marker}")
        # 1b. Check explicit refusal / preservation patterns
        is_explicit_refusal = False
        if re.search(r"\b(don't|do not|dont|never|not)\s+(delete|erase|remove|close|destroy|purge|wipe)\b", text_lower):
            if not re.search(r"\b(do not|don't)\s+hesitate\s+to\s+(delete|erase|remove)\b", text_lower):
                is_explicit_refusal = True
        elif re.search(r"\bnot\s+(asking|requesting)\s+(for\s+)?(deletion|to\s+delete)\b", text_lower):
            is_explicit_refusal = True
        elif re.search(r"\b(do not|don't)\s+close\b", text_lower):
            is_explicit_refusal = True
        else:
            m = re.search(r"\b(keep|leave)\s+(my|the)?\s*(account|profile|data|history)\b", text_lower)
            if m:
                prefix = text_lower[:m.start()].strip()
                if not re.search(r"\b(not|don't|do not|dont|never|no|without)\s*(want\s*to)?$", prefix):
                    is_explicit_refusal = True

        if is_explicit_refusal:
            return IntentResult(
                authorized=False, confidence=0.98, intent="NON_DELETION",
                reasons=reasons + ["Explicit refusal/preservation pattern detected in request text"],
                language=lang, negation_detected=True, partial_scope=partial_scope,
            )

        # 2. Check deletion verbs
        del_verbs = DELETION_VERBS.get(lang, []) + DELETION_VERBS.get("en", [])
        deletion_score = _count_keywords(text_lower, del_verbs)
        if deletion_score == 0:
            _stems = [
                "delet", "eras", "remov", "clos", "destroy", "purge", "wipe", "expung",
                "supprim", "effac", "ferm", "annul", "exclu", "apag", "elimin", "borr",
                "suprim", "tilg", "vernicht", "wisch", "cancell", "suppression", "effacement",
                "삭제", "탈퇴", "注销", "删除"
            ]
            for stem in _stems:
                if stem in text_lower:
                    deletion_score = 1
                    reasons.append(f"Deletion stem found ({stem})")
                    break

        if deletion_score > 0:
            reasons.append(f"Deletion verbs found ({deletion_score})")

        # 3. Check negation near deletion verb
        neg_markers = NEGATION_MARKERS.get(lang, []) + NEGATION_MARKERS.get("en", [])
        if deletion_score > 0:
            if lang in ("ja", "zh", "ko"):
                for neg in NEGATION_MARKERS.get(lang, []):
                    if neg in text_lower:
                        negation_detected = True
                        reasons.append(f"Negation marker ({neg}) detected in CJK text")
                        break
            if not negation_detected and _find_negation_in_window(text_lower, neg_markers, window_size=5):
                negation_detected = True
                reasons.append("Negation marker within window of deletion verb")

        # 4. Check non-deletion keywords
        non_del_keywords = NON_DELETION_KEYWORDS.get(lang, []) + NON_DELETION_KEYWORDS.get("en", [])
        non_deletion_score = _count_keywords(text_lower, non_del_keywords)
        if non_deletion_score > 0:
            reasons.append(f"Non-deletion keywords found ({non_deletion_score})")

        # 5. Check partial scope markers
        scope_markers = PARTIAL_SCOPE_MARKERS.get(lang, []) + PARTIAL_SCOPE_MARKERS.get("en", [])
        for marker in scope_markers:
            if marker in text_lower:
                partial_scope = True
                reasons.append(f"Partial scope marker detected: {marker}")
                break
        if not partial_scope:
            if re.search(r'\b(marketing|newsletter|promotional|advertising|analytics)\b.*?\b(only|just|uniquement|seulement|nur|solo|apenas)\b', text_lower) or \
               re.search(r'\b(only|just|uniquement|seulement|nur|solo|apenas)\b.*?\b(marketing|newsletter|promotional|advertising|analytics)\b', text_lower):
                partial_scope = True
                reasons.append("Partial scope pattern detected (marketing/promotions only)")

        # Decision Logic
        if hypothetical:
            return IntentResult(
                authorized=False, confidence=0.95, intent="NON_DELETION",
                reasons=reasons + ["Hypothetical/inquiry request — not an actionable deletion instruction"],
                language=lang, negation_detected=negation_detected, partial_scope=partial_scope,
            )

        if negation_detected and deletion_score > 0:
            return IntentResult(
                authorized=False, confidence=0.95, intent="NON_DELETION",
                reasons=reasons + ["Negation detected near deletion verb — request explicitly refuses deletion"],
                language=lang, negation_detected=True, partial_scope=partial_scope,
            )

        if partial_scope:
            return IntentResult(
                authorized=False, confidence=0.9, intent="NON_DELETION",
                reasons=reasons + ["Partial scope detected — request targets only specific marketing/newsletter preferences"],
                language=lang, negation_detected=negation_detected, partial_scope=True,
            )

        # Non-deletion overrides without deletion intent
        if non_deletion_score > 0 and deletion_score == 0:
            return IntentResult(
                authorized=False, confidence=0.95, intent="NON_DELETION",
                reasons=reasons + ["Only non-deletion keywords found (access/export/rectification/opt-out/password)"],
                language=lang, negation_detected=negation_detected, partial_scope=partial_scope,
            )

        # Clear deletion
        if deletion_score > 0 and non_deletion_score == 0:
            return IntentResult(
                authorized=True, confidence=0.95, intent="DELETION",
                reasons=reasons + ["Clear deletion intent without conflicting non-deletion requests"],
                language=lang, negation_detected=negation_detected, partial_scope=partial_scope,
            )

        # Mixed request precedence rules:
        if deletion_score > 0 and non_deletion_score > 0:
            # Check if export/access is a preparatory step to deletion
            # e.g., "export my data and then delete my account" or "send copy then close"
            preparatory_patterns = [
                r"(export|download|copy|send).*?(then|and then|before|after which).*?(delete|close|erase|remove)",
                r"(d'abord|avant).*?(supprimer|effacer)",
                r"(zuerst).*?(löschen)",
                r"(primero).*?(eliminar|borrar)",
            ]
            is_preparatory = any(re.search(pat, text_lower) for pat in preparatory_patterns)
            if is_preparatory:
                return IntentResult(
                    authorized=True, confidence=0.85, intent="DELETION",
                    reasons=reasons + ["Mixed request where non-deletion action is preparatory to final deletion"],
                    language=lang, negation_detected=negation_detected, partial_scope=partial_scope,
                )

            # Check if user says "do not delete, only export" or "just export, keep account"
            override_patterns = [
                r"(do not|don't|no).*?(delete|close).*?(only|just).*?(export|access|correct|update)",
                r"(solo|apenas|seulement|nur).*?(export|acceso|zugang)",
            ]
            is_override = any(re.search(pat, text_lower) for pat in override_patterns)
            if is_override:
                return IntentResult(
                    authorized=False, confidence=0.95, intent="NON_DELETION",
                    reasons=reasons + ["Request explicitly prioritizes non-deletion over deletion"],
                    language=lang, negation_detected=True, partial_scope=partial_scope,
                )

            # If deletion intent is dominant and explicit
            if deletion_score >= non_deletion_score:
                return IntentResult(
                    authorized=True, confidence=0.8, intent="DELETION",
                    reasons=reasons + ["Deletion request accompanied by incidental data reference"],
                    language=lang, negation_detected=negation_detected, partial_scope=partial_scope,
                )

            return IntentResult(
                authorized=False, confidence=0.5, intent="AMBIGUOUS",
                reasons=reasons + ["Conflicting non-deletion request dominates — defaulting to NOT_APPLICABLE"],
                language=lang, negation_detected=negation_detected, partial_scope=partial_scope,
            )

        return IntentResult(
            authorized=False, confidence=0.8, intent="NON_DELETION",
            reasons=reasons + ["No deletion intent detected in request text"],
            language=lang, negation_detected=negation_detected, partial_scope=partial_scope,
        )


def classify_intent(request_text: str, llm_enabled: bool = False) -> IntentResult:
    classifier = IntentClassifier(llm_enabled=llm_enabled)
    return classifier.classify(request_text)